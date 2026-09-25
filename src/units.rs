//! Units and pure math: rao/TAO conversion, fee margins, slippage limits.
//!
//! Every on-chain amount (TAO and alpha) is an integer number of rao: 1 TAO = 1 alpha = 1e9 rao.
//! Nothing here uses floating point.

use crate::Error;

/// Rao per whole TAO / alpha.
pub const RAO_PER_TAO: u64 = 1_000_000_000;
/// Basis points in 100 %.
pub const BPS: u64 = 10_000;

/// Parse a decimal amount ("1", "0.5", "12.000000001") into rao. At most 9 decimals.
pub fn parse_amount(s: &str) -> Result<u64, Error> {
    let bad = || Error::Config(format!("invalid amount {s:?}"));
    let s = s.trim();
    let (int, frac) = s.split_once('.').unwrap_or((s, ""));
    if int.is_empty() && frac.is_empty()
        || frac.len() > 9
        || !int.chars().chain(frac.chars()).all(|c| c.is_ascii_digit())
    {
        return Err(bad());
    }
    let int: u64 = if int.is_empty() {
        0
    } else {
        int.parse().map_err(|_| bad())?
    };
    let frac_rao: u64 = format!("{frac:0<9}").parse().map_err(|_| bad())?;
    int.checked_mul(RAO_PER_TAO)
        .and_then(|v| v.checked_add(frac_rao))
        .ok_or_else(bad)
}

/// Format rao as a decimal with 9 places ("1.500000000").
pub fn format_amount(rao: u64) -> String {
    format!("{}.{:09}", rao / RAO_PER_TAO, rao % RAO_PER_TAO)
}

/// `value * (1 + bps/10000)`, rounded up, saturating.
pub fn add_bps_ceil(value: u64, bps: u64) -> u64 {
    let v = value as u128 * (BPS + bps) as u128;
    u64::try_from(v.div_ceil(BPS as u128)).unwrap_or(u64::MAX)
}

/// TAO the treasury must send so the payment wallet can pay `fees` (sum of estimated fees):
/// fees plus a safety margin plus the existential deposit (fees are withdrawn with
/// `Preservation::Preserve`, so the account must stay alive), minus what the wallet already holds.
pub fn funding_needed(
    fees: u64,
    margin_bps: u64,
    existential_deposit: u64,
    current_free: u64,
) -> u64 {
    add_bps_ceil(fees, margin_bps)
        .saturating_add(existential_deposit)
        .saturating_sub(current_free)
}

/// `add_stake_limit` limit price (rao of TAO per 1 alpha): the worst price we accept when buying,
/// i.e. current price raised by `slippage_bps`. Never below 1 rao.
pub fn buy_limit_price(current_price: u64, slippage_bps: u64) -> u64 {
    add_bps_ceil(current_price, slippage_bps).max(1)
}

/// Alpha received for `tao` at `price` (rao per alpha), ignoring pool impact. Used for display and
/// for valuing a received alpha payment in TAO.
pub fn alpha_value_in_tao(alpha: u64, price: u64) -> u64 {
    u64::try_from(alpha as u128 * price as u128 / RAO_PER_TAO as u128).unwrap_or(u64::MAX)
}

/// Spendable TAO for `buyback_all`: free balance minus fee reserve minus existential deposit.
pub fn spendable(free: u64, fee_reserve: u64, existential_deposit: u64) -> u64 {
    free.saturating_sub(fee_reserve)
        .saturating_sub(existential_deposit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_format() {
        assert_eq!(parse_amount("1").unwrap(), RAO_PER_TAO);
        assert_eq!(parse_amount("0.5").unwrap(), 500_000_000);
        assert_eq!(parse_amount(".000000001").unwrap(), 1);
        assert_eq!(parse_amount("12.000000001").unwrap(), 12_000_000_001);
        for bad in [
            "",
            ".",
            "1.0000000001",
            "-1",
            "1e9",
            "abc",
            "99999999999999999999",
        ] {
            assert!(parse_amount(bad).is_err(), "{bad}");
        }
        assert_eq!(format_amount(1_500_000_000), "1.500000000");
        assert_eq!(
            parse_amount(&format_amount(123_456_789_012)).unwrap(),
            123_456_789_012
        );
    }

    #[test]
    fn fee_math() {
        assert_eq!(add_bps_ceil(1000, 5000), 1500);
        assert_eq!(add_bps_ceil(1, 1), 2); // rounds up
        assert_eq!(add_bps_ceil(u64::MAX, 5000), u64::MAX);
        // 2 fees of 100k, +50 %, ED 500, wallet empty
        assert_eq!(funding_needed(200_000, 5000, 500, 0), 300_500);
        // already partially funded
        assert_eq!(funding_needed(200_000, 5000, 500, 300_000), 500);
        assert_eq!(funding_needed(200_000, 5000, 500, 1_000_000), 0);
        assert_eq!(
            spendable(10 * RAO_PER_TAO, RAO_PER_TAO, 500),
            9 * RAO_PER_TAO - 500
        );
        assert_eq!(spendable(100, 1000, 500), 0);
    }

    #[test]
    fn slippage_math() {
        // price 0.02 TAO/alpha, 1 % slippage -> 0.0202
        assert_eq!(buy_limit_price(20_000_000, 100), 20_200_000);
        assert_eq!(buy_limit_price(0, 100), 1);
        assert_eq!(buy_limit_price(RAO_PER_TAO, 0), RAO_PER_TAO);
        assert_eq!(alpha_value_in_tao(2 * RAO_PER_TAO, 20_000_000), 40_000_000);
    }
}
