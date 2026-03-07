from ecdsa import SigningKey, SECP256k1  # 用于 secp256k1 私钥和公钥生成
import hashlib                           # SHA256 和 RIPEMD160 哈希
import base58                            # Base58Check 编码（WIF、P2PKH）

# ------------------------
# Helper functions
# ------------------------
def sha256(data):                         # 计算 SHA256
    return hashlib.sha256(data).digest()  # 返回字节形式

def ripemd160(data):                       # 计算 RIPEMD160
    h = hashlib.new('ripemd160')
    h.update(data)
    return h.digest()                      # 返回字节形式

# ------------------------
# Bech32 encoding (BIP173 / BIP84)
# ------------------------
CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'  # Bech32 字符集

def bech32_polymod(values):                  # Bech32 多项式校验
    GENERATOR = [0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3]
    checksum = 1
    for value in values:
        top_bits = (checksum >> 25)
        checksum = ((checksum & 0x1ffffff) << 5) ^ value
        for i in range(5):
            if ((top_bits >> i) & 1) != 0:
                checksum ^= GENERATOR[i]
    return checksum

def bech32_hrp_expand(hrp):                 # 扩展 human readable part
    result = []
    for char in hrp:
        result.append(ord(char) >> 5)
    result.append(0)
    for char in hrp:
        result.append(ord(char) & 31)
    return result

def bech32_create_checksum(hrp, data):     # 创建 Bech32 校验码
    values = bech32_hrp_expand(hrp)
    for d in data:
        values.append(d)
    for i in range(6):
        values.append(0)
    polymod = bech32_polymod(values) ^ 1
    checksum = []
    for i in range(6):
        checksum_value = (polymod >> (5 * (5 - i))) & 31
        checksum.append(checksum_value)
    return checksum

def bech32_encode(hrp, data):               # 编码为 Bech32 地址
    checksum = bech32_create_checksum(hrp, data)
    combined = []
    for d in data:
        combined.append(d)
    for c in checksum:
        combined.append(c)
    result = hrp + '1'
    for value in combined:
        result += CHARSET[value]
    return result

def convert_bits(data, from_bits, to_bits, pad=True):  # 8bit 转 5bit
    acc = 0
    bits = 0
    result = []
    max_value = (1 << to_bits) - 1
    for b in data:
        acc = (acc << from_bits) | b
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            value = (acc >> bits) & max_value
            result.append(value)
    if pad and bits > 0:
        value = (acc << (to_bits - bits)) & max_value
        result.append(value)
    return result

# ------------------------
# Batch key generation for mainnet
# ------------------------
def generate_batch(count):                 # count: 批量生成数量
    batch_result = []

    wif_prefix = b'\x80'                    # 主网 WIF 前缀
    p2pkh_prefix = b'\x00'                  # 主网 P2PKH 地址前缀
    bech32_hrp = 'bc'                       # 主网 Bech32 hrp

    for i in range(count):
        # 生成私钥
        signing_key = SigningKey.generate(curve=SECP256k1)
        private_key_bytes = signing_key.to_string()             # 32 字节

        # WIF 私钥（压缩格式，钱包可导入）
        extended_key = wif_prefix + private_key_bytes + b'\x01'  # 压缩标记
        checksum = sha256(sha256(extended_key))[0:4]             # 双 SHA256 校验
        wif_key = base58.b58encode(extended_key + checksum).decode()  # Base58Check

        # 压缩公钥
        verifying_key = signing_key.get_verifying_key()
        public_key_bytes = verifying_key.to_string()
        if public_key_bytes[63] % 2 == 0:
            prefix_byte = b'\x02'
        else:
            prefix_byte = b'\x03'
        compressed_public_key = prefix_byte + public_key_bytes[0:32]

        # P2PKH 地址
        pubkey_sha256 = sha256(compressed_public_key)
        pubkey_hash = ripemd160(pubkey_sha256)
        address_bytes = p2pkh_prefix + pubkey_hash
        checksum_address = sha256(sha256(address_bytes))[0:4]
        p2pkh_address = base58.b58encode(address_bytes + checksum_address).decode()

        # BIP84 Bech32 地址
        witness_version = 0
        data = [witness_version]                           # witness version
        converted_bits = convert_bits(pubkey_hash, 8, 5)   # 8bit->5bit
        for b in converted_bits:
            data.append(b)
        bip84_address = bech32_encode(bech32_hrp, data)

        # 保存结果
        batch_result.append({
            'private_key_hex': private_key_bytes.hex(),
            'wif': wif_key,
            'p2pkh': p2pkh_address,
            'bip84': bip84_address
        })

    return batch_result

# ------------------------
# 示例：生成 5 个密钥
# ------------------------
batch_keys = generate_batch(5)               # 只生成主网密钥
for index in range(len(batch_keys)):
    key_info = batch_keys[index]
    print("\n--- Key", index + 1, "---")
    print("Private Key (hex):", key_info['private_key_hex'])  # 生成原始私钥
    print("WIF:", key_info['wif'])                              # 钱包可导入的 WIF
    print("P2PKH:", key_info['p2pkh'])                          # 传统地址
    print("BIP84:", key_info['bip84'])                          # SegWit 地址（Bech32）
