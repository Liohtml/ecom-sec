//! Rough cost estimate from token usage (USD, Anthropic first-party list
//! prices per million tokens; 5-minute cache writes).

use crate::client::Usage;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Pricing {
    pub input: f64,
    pub output: f64,
    pub cache_write: f64,
    pub cache_read: f64,
}

/// Prices for the models the audit is meant to run on.  Unknown models fall
/// back to `None`; the report then says that the estimate is unavailable.
pub fn pricing_for(model: &str) -> Option<Pricing> {
    let p = match model {
        "claude-sonnet-5-5" | "claude-sonnet-5" => Pricing {
            input: 2.0,
            output: 10.0,
            cache_write: 2.5,
            cache_read: 0.2,
        },
        "claude-opus-5-5" => Pricing {
            input: 4.0,
            output: 20.0,
            cache_write: 5.0,
            cache_read: 0.2,
        },
        "claude-opus-5" | "claude-opus-4-8" | "claude-opus-4-7" | "claude-opus-4-6" => Pricing {
            input: 5.0,
            output: 25.0,
            cache_write: 6.25,
            cache_read: 0.5,
        },
        "claude-haiku-5-5" => Pricing {
            input: 0.1,
            output: 0.5,
            cache_write: 0.125,
            cache_read: 0.01,
        },
        _ => return None,
    };
    Some(p)
}

/// Estimated cost in USD, `None` for models without a price entry.
pub fn estimate_cost(model: &str, usage: &Usage) -> Option<f64> {
    let p = pricing_for(model)?;
    let m = 1_000_000.0;
    Some(
        usage.input_tokens as f64 * p.input / m
            + usage.output_tokens as f64 * p.output / m
            + usage.cache_creation_input_tokens as f64 * p.cache_write / m
            + usage.cache_read_input_tokens as f64 * p.cache_read / m,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn estimates_sonnet_cost() {
        let u = Usage {
            input_tokens: 1_000_000,
            output_tokens: 100_000,
            cache_creation_input_tokens: 0,
            cache_read_input_tokens: 1_000_000,
        };
        let c = estimate_cost("claude-sonnet-5-5", &u).unwrap();
        assert!((c - 3.2).abs() < 1e-9, "{c}");
        assert!(estimate_cost("unknown", &u).is_none());
    }
}
