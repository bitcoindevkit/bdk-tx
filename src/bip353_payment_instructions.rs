/// This crate adds support for BIP 353 DNS payment instructions support
///
use crate::bitcoin::{Amount, Network, ScriptBuf};
use alloc::vec::Vec;
use bitcoin_payment_instructions::{
    amount, dns_resolver::DNSHrnResolver, hrn_resolution::HrnResolver,
    FixedAmountPaymentInstructions, ParseError, PaymentInstructions, PaymentMethod,
    PaymentMethodType,
};
use core::{net::SocketAddr, str::FromStr};

async fn parse_dns_instructions(
    hrn: &str,
    resolver: &impl HrnResolver,
    network: Network,
) -> Result<PaymentInstructions, ParseError> {
    let instructions = PaymentInstructions::parse(hrn, network, resolver, true).await?;

    Ok(instructions)
}

pub struct Payment {
    pub script: ScriptBuf,
    pub amount: Amount,
    pub dnssec_proof: Option<Vec<u8>>,
}

fn process_fixed_instructions(
    amount: Amount,
    instructions: &FixedAmountPaymentInstructions,
) -> Result<Payment, ParseError> {
    // Look for on chain payment method as it's the only one we can support
    let PaymentMethod::OnChain(addr) = instructions
        .methods()
        .iter()
        .find(|ix| matches!(ix, PaymentMethod::OnChain(_)))
        .map(|pm| pm)
        .unwrap()
    else {
        return Err(ParseError::InvalidInstructions(
            "Unsupported payment method",
        ));
    };

    let Some(onchain_amount) = instructions.onchain_payment_amount() else {
        return Err(ParseError::InvalidInstructions(
            "On chain amount should be specified",
        ));
    };

    // We need this conversion since Amount from instructions is different from Amount from bitcoin
    let onchain_amount = Amount::from_sat(onchain_amount.sats_rounding_up());

    if onchain_amount != amount {
        return Err(ParseError::InvalidInstructions(
            "Mismatched amount expected , got",
        ));
    }

    Ok(Payment {
        script: addr.script_pubkey(),
        amount: onchain_amount,
        dnssec_proof: instructions.bip_353_dnssec_proof().clone(),
    })
}

// If dns instructions provides a fixed amount we can allow the user not putting an amount?
pub async fn resolve_dns_recipient(
    hrn: &str,
    amount: Amount,
    network: Network,
) -> Result<Payment, ParseError> {
    let resolver = DNSHrnResolver(SocketAddr::from_str("8.8.8.8:53").expect("Should not fail."));
    let payment_instructions = parse_dns_instructions(hrn, &resolver, network).await?;

    match payment_instructions {
        PaymentInstructions::ConfigurableAmount(instructions) => {
            // Look for on chain payment method as it's the only one we can support
            if instructions
                .methods()
                .find(|method| matches!(method.method_type(), PaymentMethodType::OnChain))
                .is_none()
            {
                return Err(ParseError::InvalidInstructions(
                    "Unsupported payment method",
                ));
            }

            let min_amount = instructions.min_amt();
            let max_amount = instructions.max_amt();

            if min_amount.is_some() {
                let min_amount = min_amount
                    .map(|a| Amount::from_sat(a.sats_rounding_up()))
                    .unwrap();
                if amount < min_amount {
                    return Err(ParseError::InvalidInstructions(
                        "Amount lesser than min amount",
                    ));
                }
            }

            if max_amount.is_some() {
                let max_amount = max_amount
                    .map(|a| Amount::from_sat(a.sats_rounding_up()))
                    .unwrap();
                if amount > max_amount {
                    return Err(ParseError::InvalidInstructions(
                        "Amount greater than max amount",
                    ));
                }
            }

            let fixed_instructions = instructions
                .set_amount(
                    amount::Amount::from_sats(amount.to_sat()).unwrap(),
                    &resolver,
                )
                .await
                .map_err(|s| ParseError::InvalidInstructions(s))?;

            process_fixed_instructions(amount, &fixed_instructions)
        }

        PaymentInstructions::FixedAmount(instructions) => {
            process_fixed_instructions(amount, &instructions)
        }
    }
}

// pub async fn resolve_dns_recipient_with_resolver() -> Result<Payment, ParseError>>;
