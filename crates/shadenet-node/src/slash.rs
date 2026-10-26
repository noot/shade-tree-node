//! What an over-spend reveals (`packages/node/lib/rln.mjs` `reconstructSecret`,
//! `resolveSlashLeaf`). Two shares on the line `y = secret + a1*x` give the secret; the leaf
//! to slash is the tier whose rate commitment is in the admitted set. Submission on chain is
//! not in this build: the outcome is logged, never the secret.

use ark_bn254::Fr;
use ark_ff::Field;
use shadenet_rln::tree::{fr_to_dec, rate_commitment};

use crate::spent::Share;
use crate::verify::parse_field;

pub(crate) struct Tier {
    pub(crate) commitment: String,
    pub(crate) limit: u64,
    pub(crate) resolved: bool,
}

pub(crate) fn reconstruct_secret(a: &Share, b: &Share) -> Result<Fr, String> {
    let (xa, ya) = (parse_field(&a.x)?, parse_field(&a.y)?);
    let (xb, yb) = (parse_field(&b.x)?, parse_field(&b.y)?);
    let dx = xb - xa;
    let slope = (yb - ya)
        * dx.inverse()
            .ok_or_else(|| "identical evaluation points".to_string())?;
    Ok(ya - slope * xa)
}

/// The leaf one secret could sit behind, one candidate per tier, preferring the one the
/// node admits; the default tier when none is.
pub(crate) fn resolve_tier(
    secret: Fr,
    tiers: &[u64],
    default: u64,
    has_leaf: impl Fn(&str) -> bool,
) -> Tier {
    let candidates: Vec<Tier> = tiers
        .iter()
        .map(|limit| Tier {
            commitment: fr_to_dec(&rate_commitment(secret, *limit)),
            limit: *limit,
            resolved: false,
        })
        .collect();
    let mut candidates = candidates;
    if let Some(index) = candidates.iter().position(|c| has_leaf(&c.commitment)) {
        let mut found = candidates.swap_remove(index);
        found.resolved = true;
        return found;
    }
    let index = candidates
        .iter()
        .position(|c| c.limit == default)
        .unwrap_or(0);
    candidates.swap_remove(index)
}

/// Record the over-spend. Only the public leaf is named, never any byte of the secret.
pub(crate) fn dry_run(tier: &Tier) {
    let prefix: String = tier.commitment.chars().take(18).collect();
    tracing::info!(
        commitment = format!("{prefix}.."),
        limit = tier.limit,
        resolved = tier.resolved,
        "SLASH (dry-run)"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use shadenet_rln::tree::parse_fr;

    #[test]
    fn two_shares_give_back_the_secret() {
        let secret = parse_fr("111").unwrap();
        let slope = parse_fr("12345").unwrap();
        let at = |x: u64| {
            let x = Fr::from(x);
            Share {
                x: fr_to_dec(&x),
                y: fr_to_dec(&(secret + slope * x)),
            }
        };
        assert_eq!(reconstruct_secret(&at(3), &at(7)).unwrap(), secret);
        assert!(reconstruct_secret(&at(3), &at(3)).is_err());
    }

    #[test]
    fn the_tier_in_the_set_wins_else_the_default() {
        let secret = parse_fr("111").unwrap();
        let leaf32 = fr_to_dec(&rate_commitment(secret, 32));
        let tier = resolve_tier(secret, &[8, 32], 8, |leaf| leaf == leaf32);
        assert!(tier.resolved);
        assert_eq!(tier.limit, 32);
        let tier = resolve_tier(secret, &[8, 32], 8, |_| false);
        assert!(!tier.resolved);
        assert_eq!(tier.limit, 8);
        assert_eq!(tier.commitment, fr_to_dec(&rate_commitment(secret, 8)));
    }
}
