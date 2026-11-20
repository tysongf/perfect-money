use crate::error::MonetaryError;

/// Micro-PM & micro-numeraire fixed-point unit (`1e6`), matching `ledger_core` 1:1.
pub const PM_SCALE: u128 = 1_000_000;

/// Dimensionless ratio, rate, price, weight, and collateral nano-unit fixed-point scale (`1e9`).
pub const SCALE: u128 = 1_000_000_000;
pub const SCALE_I128: i128 = 1_000_000_000;

/// Ratio between `SCALE` (`1e9`) and `PM_SCALE` (`1e6`).
pub const SCALE_TO_PM: u128 = 1_000;

/// Internal 18-decimal precision scale for transcendental `ln` / `exp`.
pub const WAD: u128 = 1_000_000_000_000_000_000;
pub const LN2_WAD: u128 = 693_147_180_559_945_309;
pub const SQRT2_WAD: u128 = 1_414_213_562_373_095_049;
pub const INV_SQRT2_WAD: u128 = 707_106_781_186_547_524;

/// Converts whole PM tokens into micro-PM (`1e6`).
pub const fn pm_from_whole(n: u64) -> u128 {
    (n as u128) * PM_SCALE
}

/// Converts basis points (`1 bps = 0.0001`) into `SCALE` (`1e9`) units.
pub const fn scale_from_bps(bps: u64) -> u128 {
    (bps as u128) * 100_000
}

/// Exact unsigned 128x128 -> 256-bit product `(hi, lo)`.
pub fn mul_u128_wide(a: u128, b: u128) -> (u128, u128) {
    let mask = u64::MAX as u128;
    let a_lo = a & mask;
    let a_hi = a >> 64;
    let b_lo = b & mask;
    let b_hi = b >> 64;

    let p_ll = a_lo * b_lo;
    let p_lh = a_lo * b_hi;
    let p_hl = a_hi * b_lo;
    let p_hh = a_hi * b_hi;

    let mid = (p_ll >> 64) + (p_lh & mask) + (p_hl & mask);
    let lo = (p_ll & mask) | (mid << 64);
    let hi = p_hh + (p_lh >> 64) + (p_hl >> 64) + (mid >> 64);
    (hi, lo)
}

/// Exact division of a 256-bit unsigned integer `(hi, lo)` by `d`, returning `(quotient, remainder)`.
pub fn div_u256_by_u128(hi: u128, lo: u128, d: u128) -> Result<(u128, u128), MonetaryError> {
    if d == 0 {
        return Err(MonetaryError::DivisionByZero);
    }
    if hi >= d {
        return Err(MonetaryError::MathOverflow);
    }
    if hi == 0 {
        return Ok((lo / d, lo % d));
    }

    let mut q: u128 = 0;
    let mut rem: u128 = hi;
    for bit in (0..128).rev() {
        let overflow = (rem >> 127) != 0;
        rem = (rem << 1) | ((lo >> bit) & 1);
        q <<= 1;
        if overflow || rem >= d {
            rem = rem.wrapping_sub(d);
            q |= 1;
        }
    }
    Ok((q, rem))
}

fn mul_div_rem(a: u128, b: u128, d: u128) -> Result<(u128, u128), MonetaryError> {
    let (hi, lo) = mul_u128_wide(a, b);
    div_u256_by_u128(hi, lo, d)
}

/// Computes `floor(a * b / d)` using an exact 256-bit intermediate product.
pub fn mul_div_floor(a: u128, b: u128, d: u128) -> Result<u128, MonetaryError> {
    let (q, _) = mul_div_rem(a, b, d)?;
    Ok(q)
}

/// Computes `ceil(a * b / d)` using an exact 256-bit intermediate product.
pub fn mul_div_ceil(a: u128, b: u128, d: u128) -> Result<u128, MonetaryError> {
    let (q, rem) = mul_div_rem(a, b, d)?;
    if rem > 0 {
        q.checked_add(1).ok_or(MonetaryError::MathOverflow)
    } else {
        Ok(q)
    }
}

/// Computes `round_half_up(a * b / d)` using an exact 256-bit intermediate product.
pub fn mul_div_round(a: u128, b: u128, d: u128) -> Result<u128, MonetaryError> {
    let (q, rem) = mul_div_rem(a, b, d)?;
    if rem > (d - 1) / 2 {
        q.checked_add(1).ok_or(MonetaryError::MathOverflow)
    } else {
        Ok(q)
    }
}

/// Computes `trunc(a * b / d)` for signed 128-bit factors divided by an unsigned `u128`.
pub fn mul_div_signed_trunc(a: i128, b: i128, d: u128) -> Result<i128, MonetaryError> {
    let neg = (a < 0) ^ (b < 0);
    let q = mul_div_floor(a.unsigned_abs(), b.unsigned_abs(), d)?;
    signed_from_mag(neg, q)
}

fn mul_div_signed_round(a: i128, b: i128, d: u128) -> Result<i128, MonetaryError> {
    let neg = (a < 0) ^ (b < 0);
    let q = mul_div_round(a.unsigned_abs(), b.unsigned_abs(), d)?;
    signed_from_mag(neg, q)
}

fn signed_from_mag(neg: bool, mag: u128) -> Result<i128, MonetaryError> {
    if neg {
        let max_neg_mag = (i128::MAX as u128) + 1;
        if mag > max_neg_mag {
            return Err(MonetaryError::MathOverflow);
        }
        if mag == max_neg_mag {
            Ok(i128::MIN)
        } else {
            Ok(-(mag as i128))
        }
    } else {
        if mag > i128::MAX as u128 {
            return Err(MonetaryError::MathOverflow);
        }
        Ok(mag as i128)
    }
}

/// Exact integer square root `floor(sqrt(hi * 2^128 + lo))`.
pub fn isqrt_u256(hi: u128, lo: u128) -> u128 {
    if hi == 0 && lo == 0 {
        return 0;
    }
    let mut low: u128 = 1;
    let mut high: u128 = u128::MAX;
    while low < high {
        let mid = low + (high - low).div_ceil(2);
        let (sq_hi, sq_lo) = mul_u128_wide(mid, mid);
        if sq_hi < hi || (sq_hi == hi && sq_lo <= lo) {
            low = mid;
        } else {
            high = mid - 1;
        }
    }
    low
}

/// Deterministic natural logarithm `ln(x_wad / WAD) * WAD` using range reduction and odd `atanh` series.
pub fn ln_wad(x_wad: u128) -> Result<i128, MonetaryError> {
    if x_wad == 0 {
        return Err(MonetaryError::InvalidParameter(
            "ln_wad input must be positive".to_string(),
        ));
    }
    if x_wad == WAD {
        return Ok(0);
    }

    let mut m = x_wad;
    let mut k: i128 = 0;
    while m >= SQRT2_WAD {
        m >>= 1;
        k += 1;
    }
    while m < INV_SQRT2_WAD {
        m <<= 1;
        k -= 1;
    }

    let num = (m as i128) - (WAD as i128);
    let den = m + WAD;
    let z_wad = mul_div_signed_round(num, WAD as i128, den)?;
    let z2_wad = mul_div_round(z_wad.unsigned_abs(), z_wad.unsigned_abs(), WAD)?;

    let mut term = z_wad;
    let mut sum: i128 = 0;
    for n in 0..13u128 {
        sum += term / ((2 * n + 1) as i128);
        term = mul_div_signed_trunc(term, z2_wad as i128, WAD)?;
    }

    let ln_m = 2 * sum;
    k.checked_mul(LN2_WAD as i128)
        .and_then(|base| base.checked_add(ln_m))
        .ok_or(MonetaryError::MathOverflow)
}

/// Deterministic natural exponential `exp(x_wad / WAD) * WAD` via range reduction + Taylor series.
pub fn exp_wad(x_wad: i128) -> Result<u128, MonetaryError> {
    let min_x = -42 * (WAD as i128);
    let max_x = 44 * (WAD as i128);
    if x_wad < min_x {
        return Ok(0);
    }
    if x_wad > max_x {
        return Err(MonetaryError::MathOverflow);
    }
    if x_wad == 0 {
        return Ok(WAD);
    }

    let half_ln2 = (LN2_WAD as i128) / 2;
    let k = if x_wad >= 0 {
        (x_wad + half_ln2) / (LN2_WAD as i128)
    } else {
        (x_wad - half_ln2) / (LN2_WAD as i128)
    };
    let r = x_wad - k * (LN2_WAD as i128);

    let mut exp_r: i128 = WAD as i128;
    let mut term: i128 = WAD as i128;
    for n in 1..=24u128 {
        term = mul_div_signed_trunc(term, r, WAD)?;
        term /= n as i128;
        if term == 0 {
            break;
        }
        exp_r += term;
    }

    let res = exp_r as u128;
    if k >= 0 {
        res.checked_shl(k as u32).ok_or(MonetaryError::MathOverflow)
    } else {
        let shift = (-k) as u32;
        if shift >= 128 {
            Ok(0)
        } else {
            Ok((res + (1u128 << (shift - 1))) >> shift)
        }
    }
}

/// Exact half-life decay `round(value * 0.5 ^ (elapsed / half_life))`.
pub fn decay_half_life(value: u128, elapsed: u64, half_life: u64) -> Result<u128, MonetaryError> {
    if half_life == 0 {
        return Err(MonetaryError::DivisionByZero);
    }
    if value == 0 || elapsed == 0 {
        return Ok(value);
    }
    let whole_halves = elapsed / half_life;
    let rem = elapsed % half_life;
    let shifted = if whole_halves >= 128 {
        0
    } else {
        value >> (whole_halves as u32)
    };
    if shifted == 0 || rem == 0 {
        return Ok(shifted);
    }
    let neg_ln_frac = -((mul_div_round(LN2_WAD, rem as u128, half_life as u128)?) as i128);
    let factor = exp_wad(neg_ln_frac)?;
    mul_div_round(shifted, factor, WAD)
}

