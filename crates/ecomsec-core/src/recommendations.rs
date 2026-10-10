//! Prioritised recommendations ("Handlungsempfehlungen") derived from a
//! report.  Generic items apply to every platform; adapters may add their own.

use crate::finding::{Category, FindingId, Severity};
use crate::platform::PatchState;
use crate::report::Report;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecommendationGroupKind {
    /// Verify critical findings before taking the shop offline.
    CheckFirst,
    /// Immediate actions.
    Immediate,
    /// Compromise assessment steps.
    CompromiseCheck,
    /// Long-term hardening.
    Hardening,
}

impl RecommendationGroupKind {
    pub fn label(self) -> &'static str {
        match self {
            RecommendationGroupKind::CheckFirst => "Zuerst prüfen (Fehlalarme ausschließen)",
            RecommendationGroupKind::Immediate => "Sofortmaßnahmen",
            RecommendationGroupKind::CompromiseCheck => "Kompromittierungs-Prüfung",
            RecommendationGroupKind::Hardening => "Langfristige Härtung",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    pub group: RecommendationGroupKind,
    /// 1 = highest.
    pub priority: u8,
    pub title: String,
    pub detail: String,
    /// Findings that triggered this recommendation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub related: Vec<FindingId>,
}

impl Recommendation {
    pub fn new(
        group: RecommendationGroupKind,
        priority: u8,
        title: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Recommendation {
            group,
            priority,
            title: title.into(),
            detail: detail.into(),
            related: Vec::new(),
        }
    }

    pub fn related(mut self, ids: impl IntoIterator<Item = FindingId>) -> Self {
        self.related.extend(ids);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecommendationGroup {
    pub kind: RecommendationGroupKind,
    pub label: String,
    pub items: Vec<Recommendation>,
}

/// Build the recommendation list for a report.  `extra` are platform specific
/// recommendations that are merged into the same groups.
pub fn build(report: &Report, extra: Vec<Recommendation>) -> Vec<RecommendationGroup> {
    use RecommendationGroupKind as G;
    let mut recs: Vec<Recommendation> = Vec::new();
    let active = |cat: Category| -> Vec<FindingId> {
        report
            .findings
            .iter()
            .filter(|f| !f.accepted && f.category == cat)
            .map(|f| f.id.clone())
            .collect()
    };
    let has_critical = report.summary.critical > 0;

    // ------------------------------------------------------------ check first
    if has_critical {
        recs.push(Recommendation::new(
            G::CheckFirst,
            1,
            "Kritische Befunde vor dem Abschalten des Shops verifizieren",
            "Jeden kritischen Befund öffnen und prüfen, ob Datei/Eintrag bekannt ist (eigene Anpassung, \
             Plugin, Agentur). Nur bestätigte Fremddateien behandeln wie unten beschrieben. Bekannte, \
             harmlose Befunde als unbedenklich markieren (mit Begründung), damit sie künftig nicht mehr zählen.",
        ));
    }

    // ------------------------------------------------------------ immediate
    let vulnerable: Vec<_> = report
        .advisories
        .iter()
        .filter(|a| matches!(a.state, PatchState::Vulnerable | PatchState::Unknown))
        .collect();
    for adv in &vulnerable {
        let fix = adv
            .advisory
            .fixed_in
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join(" / ");
        let mut detail = format!(
            "{}. Behobene Versionen: {}.",
            adv.basis.trim_end_matches('.'),
            if fix.is_empty() {
                "siehe Hersteller".into()
            } else {
                fix
            }
        );
        if let Some(note) = &adv.advisory.backpatch_note {
            detail.push(' ');
            detail.push_str(note);
        }
        recs.push(
            Recommendation::new(
                G::Immediate,
                1,
                format!(
                    "Sicherheitspatch einspielen: {} – {}",
                    adv.advisory.id, adv.advisory.title
                ),
                detail,
            )
            .related(active(Category::PatchStatus)),
        );
    }

    let webshells = active(Category::KnownWebshell);
    let payloads = active(Category::ExploitPayload);
    let patterns = active(Category::SuspiciousPattern);
    let uploads = active(Category::CodeInUploadDir);
    let htaccess = active(Category::WebserverConfigManipulation);
    if !webshells.is_empty() || !payloads.is_empty() || !uploads.is_empty() {
        recs.push(
            Recommendation::new(
                G::Immediate,
                1,
                "Bestätigte Webshells / Exploit-Dateien isolieren",
                "Betroffene Dateien nicht einfach löschen, sondern zuerst für die Forensik sichern (Kopie \
                 außerhalb des Webroots inkl. Zeitstempel), danach entfernen oder den Zugriff per Webserver \
                 sperren. Anschließend alle Zugangsdaten rotieren (DB, Admin, FTP/SFTP, API-Keys, SMTP).",
            )
            .related(webshells.iter().chain(payloads.iter()).chain(uploads.iter()).cloned()),
        );
    }
    if !htaccess.is_empty() {
        recs.push(
            Recommendation::new(
                G::Immediate,
                1,
                "Manipulierte Webserver-Konfiguration (.htaccess/.user.ini) zurücksetzen",
                "Handler-Zuweisungen für Nicht-PHP-Dateien, auto_prepend_file und fremde RewriteRules \
                 entfernen und durch die Original-Konfiguration des Shops ersetzen.",
            )
            .related(htaccess),
        );
    }
    let payment = active(Category::PaymentConfiguration);
    if !payment.is_empty() {
        recs.push(
            Recommendation::new(
                G::Immediate,
                1,
                "Zahlungsempfänger-Konfiguration prüfen",
                "Die hinterlegte Empfänger-/Händler-Kennung hat sich seit dem letzten Scan geändert oder ist \
                 auffällig. Im Backend und beim Zahlungsanbieter verifizieren, dass Auszahlungen auf das eigene \
                 Konto laufen.",
            )
            .related(payment),
        );
    }
    let injections = active(Category::ThirdPartyInjection);
    if !injections.is_empty() {
        recs.push(
            Recommendation::new(
                G::Immediate,
                1,
                "Unbekannte Fremdskripte, Webhooks oder Apps entfernen",
                "Jeden Eintrag einer bekannten App/Agentur zuordnen. Unbekannte Script-Tags und Webhooks \
                 (vor allem zu fremden Domains) deaktivieren und die zugehörigen Zugriffstoken widerrufen.",
            )
            .related(injections),
        );
    }
    let exposed = active(Category::ExposedFile);
    if !exposed.is_empty() {
        recs.push(
            Recommendation::new(
                G::Immediate,
                2,
                "Öffentlich erreichbare Backup-/Dump-/Konfigurationsdateien entfernen",
                "Datenbank-Dumps, Archive und Konfigurationskopien aus dem Webroot entfernen oder außerhalb \
                 ablegen. Enthaltene Zugangsdaten gelten als kompromittiert und sind zu rotieren.",
            )
            .related(exposed),
        );
    }

    // ------------------------------------------------------------ compromise check
    let modified = active(Category::ModifiedSinceReference);
    let anomalies = active(Category::TimestampAnomaly);
    if !modified.is_empty() || !patterns.is_empty() || !anomalies.is_empty() {
        recs.push(
            Recommendation::new(
                G::CompromiseCheck,
                2,
                "Neue/geänderte Dateien und Code-Muster manuell prüfen",
                "Jede seit dem Referenzdatum geänderte Datei mit einer sauberen Kopie des Shops (Release-\
                 Archiv, Git, Backup) vergleichen. Unbekannte Dateien gelten bis zum Beweis des Gegenteils \
                 als Fremdcode. Zeitstempel-Anomalien deuten auf absichtlich zurückdatierte Dateien hin.",
            )
            .related(modified.iter().chain(patterns.iter()).chain(anomalies.iter()).cloned()),
        );
    }
    let traces = active(Category::AttackTrace);
    if !traces.is_empty() {
        recs.push(
            Recommendation::new(
                G::CompromiseCheck,
                1,
                "Angriffsspuren in E-Mails/Logs auswerten",
                "Die gefundenen Payloads belegen mindestens einen Angriffsversuch. Zeitpunkt mit Webserver-\
                 Logs abgleichen und prüfen, ob der Shop zu diesem Zeitpunkt bereits gepatcht war. Falls \
                 nicht: von einer Kompromittierung ausgehen und alle Zugangsdaten rotieren.",
            )
            .related(traces.clone()),
        );
    }
    let admins = active(Category::AdminAccount);
    if !admins.is_empty() {
        recs.push(
            Recommendation::new(
                G::CompromiseCheck,
                2,
                "Admin-Konten bereinigen",
                "Unbekannte oder lange ungenutzte Administratorkonten deaktivieren, Passwörter aller \
                 verbleibenden Konten ändern und Zwei-Faktor-Authentifizierung für alle Admins erzwingen.",
            )
            .related(admins),
        );
    }
    let deviations = active(Category::IntegrityDeviation);
    if !deviations.is_empty() {
        recs.push(
            Recommendation::new(
                G::CompromiseCheck,
                2,
                "Abweichungen vom Integritäts-Baseline prüfen",
                "Geänderte, fehlende oder neue Kerndateien gegen das Original-Release verifizieren und \
                 nach der Prüfung eine neue Baseline erzeugen.",
            )
            .related(deviations),
        );
    }
    if report.summary.critical > 0 || !traces.is_empty() {
        recs.push(Recommendation::new(
            G::CompromiseCheck,
            3,
            "Bei bestätigter Kompromittierung: vollständige forensische Analyse",
            "Dieser Scan ist eine Triage-Hilfe. Ein bestätigter Befund erfordert eine Analyse von \
             Webserver-Logs, Datenbank (Bestellungen, Kundendaten, Admin-Logins) und Hosting-Umgebung, \
             ggf. mit Meldepflicht nach DSGVO Art. 33 innerhalb von 72 Stunden.",
        ));
    }

    // ------------------------------------------------------------ hardening
    let perms = active(Category::ConfigPermissions);
    recs.push(
        Recommendation::new(
            G::Hardening,
            if perms.is_empty() { 3 } else { 2 },
            "Dateirechte für Konfigurationsdateien einschränken",
            "Konfigurationsdateien mit Zugangsdaten sollten nur für den Webserver-Benutzer lesbar sein \
             (z. B. 0400/0440) und nie für Gruppe/Andere schreibbar.",
        )
        .related(perms),
    );
    recs.push(Recommendation::new(
        G::Hardening,
        3,
        "PHP-Ausführung in Upload-/Medienverzeichnissen serverseitig unterbinden",
        "Per Webserver-Konfiguration (z. B. `php_flag engine off`, `RemoveHandler`, nginx `location` ohne \
         PHP-Weiterleitung) sicherstellen, dass hochgeladene Dateien nie als Code ausgeführt werden.",
    ));
    recs.push(Recommendation::new(
        G::Hardening,
        3,
        "Regelmäßigen Scan und Baseline etablieren",
        "Scan wöchentlich sowie nach jedem Update ausführen; nach verifiziertem Zustand eine Baseline \
         erzeugen, damit künftige Änderungen an Kerndateien sofort auffallen.",
    ));
    recs.push(Recommendation::new(
        G::Hardening,
        3,
        "Updates, Plugins und Zugänge im Griff behalten",
        "Sicherheitsupdates des Shopsystems zeitnah einspielen, nicht benötigte Plugins/Apps deinstallieren, \
         Zugangsdaten turnusmäßig rotieren und 2FA für alle Backend-Zugänge erzwingen. Eine Web Application \
         Firewall reduziert die Angriffsfläche zusätzlich.",
    ));

    recs.extend(extra);

    let mut groups: Vec<RecommendationGroup> = Vec::new();
    for kind in [
        G::CheckFirst,
        G::Immediate,
        G::CompromiseCheck,
        G::Hardening,
    ] {
        let mut items: Vec<Recommendation> =
            recs.iter().filter(|r| r.group == kind).cloned().collect();
        if items.is_empty() {
            continue;
        }
        items.sort_by_key(|r| r.priority);
        groups.push(RecommendationGroup {
            kind,
            label: kind.label().to_string(),
            items,
        });
    }
    groups
}

/// Severity → default priority mapping used by adapters.
pub fn priority_for(severity: Severity) -> u8 {
    match severity {
        Severity::Critical => 1,
        Severity::Warning => 2,
        Severity::Info => 3,
    }
}
