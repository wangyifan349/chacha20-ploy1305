Cargo.toml

[package]
name = "bip84_tool"
version = "0.1.0"
edition = "2021"

[dependencies]
bitcoin = "0.31"
bip39 = "1.1"
hex = "0.4"





  
src/main.rs

use bitcoin::network::constants::Network;
use bitcoin::util::bip32::{DerivationPath, ExtendedPrivKey};
use bitcoin::util::address::Address;
use bitcoin::secp256k1::Secp256k1;
use bip39::{Mnemonic, Language, Seed, MnemonicType};
use std::io::{self, Write};
use std::str::FromStr;
use hex::ToHex;

/// 配置：派生数量 N、网络（这里固定 mainnet）、account
const NUM_ADDR: usize = 5;
const NETWORK: Network = Network::Bitcoin; // 主网
const ACCOUNT: u32 = 0;

/// 从随机生成助记词与种子
fn gen_mnemonic_and_seed() -> (Mnemonic, Vec<u8>) {
    let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
    let seed = Seed::new(&mnemonic, ""); // 空 passphrase
    (mnemonic, seed.as_bytes().to_vec())
}

/// 从用户给定助记词恢复 seed（如果输入为空则生成新的）
fn seed_from_user_input() -> (Mnemonic, Vec<u8>) {
    println!("如果你有现成助记词，请粘贴（12/24 words），否则回车生成随机助记词：");
    print!("> ");
    io::stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let input = input.trim();

    if input.is_empty() {
        let (mnemonic, seed) = gen_mnemonic_and_seed();
        (mnemonic, seed)
    } else {
        let mnemonic = Mnemonic::from_phrase(input, Language::English)
            .expect("助记词无效，请使用有效的 BIP39 助记词");
        let seed = Seed::new(&mnemonic, ""); // 若需 passphrase，可修改这里
        (mnemonic, seed.as_bytes().to_vec())
    }
}

fn main() {
    // 1) 获取或生成助记词与 seed
    let (mnemonic, seed_bytes) = seed_from_user_input();
    println!("\n=== 助记词 (请安全备份，不要泄露) ===\n{}\n", mnemonic.phrase());
    println!("Seed (hex): {}\n", seed_bytes.encode_hex::<String>());

    // 2) 构造 master xprv
    let secp = Secp256k1::new();
    let master_xprv = ExtendedPrivKey::new_master(NETWORK, &seed_bytes)
        .expect("无法从 seed 构造 master xprv");
    println!("Master XPRV: {}\n", master_xprv);

    // 3) BIP84 account path m/84'/0'/ACCOUNT'
    let bip84_account_path = format!("m/84'/0'/{}'", ACCOUNT);
    let account_path = DerivationPath::from_str(&bip84_account_path).expect("无效的派生路径");
    println!("BIP84 account path: {}\n", account_path);

    let account_xprv = master_xprv.derive_priv(&secp, &account_path)
        .expect("无法派生 account xprv");
    println!("Account XPRV: {}\n", account_xprv);

    // 4) 派生并打印前 NUM_ADDR 个外部地址（change = 0）
    println!("\n=== 派生前 {} 个外部收款地址 (m/84'/0'/{}/0/i) ===\n", NUM_ADDR, ACCOUNT);
    for i in 0..NUM_ADDR {
        // 相对路径 "0/i"
        let rel = DerivationPath::from_str(&format!("0/{}", i)).unwrap();
        let full_path = account_path.extend(rel.clone());
        let child_xprv = master_xprv.derive_priv(&secp, &full_path)
            .expect("派生子私钥失败");

        let privkey = child_xprv.private_key;
        let wif = privkey.to_wif();
        let privkey_bytes = privkey.key[..].to_vec(); // 32 bytes
        let privkey_hex = privkey_bytes.encode_hex::<String>();

        let pubkey = privkey.public_key(&secp);
        let pubkey_hex = pubkey.to_string(); // compressed hex

        let address = Address::p2wpkh(&pubkey, NETWORK).expect("生成地址失败");

        println!("Index {}:", i);
        println!("  Path: {}", full_path);
        println!("  Private (hex): {}", privkey_hex);
        println!("  Private (WIF): {}", wif);
        println!("  Public (compressed hex): {}", pubkey_hex);
        println!("  Address (bech32 P2WPKH): {}\n", address);
    }

    println!("完成。请妥善保存助记词及私钥信息。");
}
