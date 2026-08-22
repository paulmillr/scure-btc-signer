#include <common/messages.h>
#include <key.h>
#include <primitives/transaction.h>
#include <psbt.h>
#include <script/signingprovider.h>
#include <streams.h>
#include <util/strencodings.h>
#include <util/translation.h>

#include <charconv>
#include <cstdint>
#include <iostream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

// Core standalone executables provide a null translator when no UI owns localization.
const TranslateFn G_TRANSLATION_FUN{nullptr};

namespace {
[[noreturn]] void Fail(const std::string& message)
{
    throw std::runtime_error(message);
}

void ExpectArgs(int argc, int expected, std::string_view usage)
{
    if (argc != expected) Fail("usage: btc-crosstest " + std::string{usage});
}

void ExpectMinArgs(int argc, int expected, std::string_view usage)
{
    if (argc < expected) Fail("usage: btc-crosstest " + std::string{usage});
}

template <typename T>
T Number(std::string_view value, std::string_view name)
{
    T result{};
    const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), result);
    if (error != std::errc{} || end != value.data() + value.size()) {
        Fail("invalid " + std::string{name} + ": " + std::string{value});
    }
    return result;
}

std::optional<uint32_t> OptionalNumber(std::string_view value, std::string_view name)
{
    if (value == "-") return std::nullopt;
    return Number<uint32_t>(value, name);
}

PartiallySignedTransaction Decode(std::string_view encoded)
{
    auto result = DecodeBase64PSBT(std::string{encoded});
    if (!result) Fail(util::ErrorString(result).original);
    return *result;
}

std::string Encode(const PartiallySignedTransaction& psbt)
{
    DataStream stream{};
    stream << psbt;
    return EncodeBase64(stream);
}

std::string EncodeTx(const CMutableTransaction& tx)
{
    DataStream stream{};
    stream << TX_WITH_WITNESS(tx);
    return HexStr(stream);
}

std::string MaybeNumber(const std::optional<uint32_t>& value)
{
    return value ? std::to_string(*value) : "null";
}

std::string Inspect(const PartiallySignedTransaction& psbt)
{
    size_t signature_inputs{0};
    size_t final_inputs{0};
    size_t partial_signatures{0};
    for (const auto& input : psbt.inputs) {
        if (input.HasSignatures()) ++signature_inputs;
        if (PSBTInputSigned(input)) ++final_inputs;
        partial_signatures += input.partial_sigs.size();
    }
    const auto locktime = psbt.ComputeTimeLock();
    const auto tx = psbt.GetUnsignedTx();
    std::ostringstream out;
    out << "{\"psbt_version\":" << psbt.GetVersion();
    out << ",\"tx_version\":" << psbt.tx_version;
    out << ",\"fallback_locktime\":" << MaybeNumber(psbt.fallback_locktime);
    out << ",\"tx_modifiable\":";
    if (psbt.m_tx_modifiable) out << psbt.m_tx_modifiable->to_ulong();
    else out << "null";
    out << ",\"computed_locktime\":" << MaybeNumber(locktime);
    out << ",\"inputs\":" << psbt.inputs.size();
    out << ",\"outputs\":" << psbt.outputs.size();
    out << ",\"signature_inputs\":" << signature_inputs;
    out << ",\"final_inputs\":" << final_inputs;
    out << ",\"partial_signatures\":" << partial_signatures;
    out << ",\"unsigned_tx\":";
    if (tx) out << '"' << EncodeTx(*tx) << '"';
    else out << "null";
    out << '}';
    return out.str();
}

std::string Roundtrip(int argc, char** argv)
{
    ExpectArgs(argc, 3, "roundtrip PSBT_BASE64");
    return Encode(Decode(argv[2]));
}

std::string Combine(int argc, char** argv)
{
    ExpectMinArgs(argc, 4, "combine PSBT_BASE64 PSBT_BASE64 [PSBT_BASE64 ...]");
    std::vector<PartiallySignedTransaction> psbts;
    for (int i = 2; i < argc; ++i) psbts.push_back(Decode(argv[i]));
    auto result = CombinePSBTs(psbts);
    if (!result) Fail("PSBTs are not compatible");
    return Encode(*result);
}

std::string Finalize(int argc, char** argv)
{
    ExpectArgs(argc, 3, "finalize PSBT_BASE64");
    auto psbt = Decode(argv[2]);
    FinalizePSBT(psbt);
    return Encode(psbt);
}

std::string Extract(int argc, char** argv)
{
    ExpectArgs(argc, 3, "extract PSBT_BASE64");
    auto psbt = Decode(argv[2]);
    CMutableTransaction tx;
    if (!FinalizeAndExtractPSBT(psbt, tx)) Fail("PSBT is incomplete");
    return EncodeTx(tx);
}

std::string Sign(int argc, char** argv)
{
    ExpectMinArgs(argc, 4, "sign PSBT_BASE64 PRIVKEY_HEX [PRIVKEY_HEX ...]");
    auto psbt = Decode(argv[2]);
    FillableSigningProvider provider;
    for (int i = 3; i < argc; ++i) {
        const auto bytes = TryParseHex<unsigned char>(argv[i]);
        if (!bytes || bytes->size() != 32) Fail("private key must be exactly 32 bytes of hex");
        CKey key;
        key.Set(bytes->begin(), bytes->end(), true);
        if (!key.IsValid()) Fail("invalid private key");
        provider.AddKey(key);
    }
    auto txdata = PrecomputePSBTData(psbt);
    if (!txdata) Fail("the transaction cannot be valid");
    for (size_t i = 0; i < psbt.inputs.size(); ++i) {
        const auto error = SignPSBTInput(
            provider,
            psbt,
            i,
            &*txdata,
            {.sighash_type = psbt.inputs[i].sighash_type, .finalize = false}
        );
        if (error != common::PSBTError::OK && error != common::PSBTError::INCOMPLETE) {
            Fail(common::PSBTErrorString(error).original);
        }
    }
    return Encode(psbt);
}

std::string AddInput(int argc, char** argv)
{
    if (argc < 5 || argc > 8) {
        Fail("usage: btc-crosstest add-input PSBT_BASE64 TXID VOUT "
             "[SEQUENCE|-] [HEIGHT_LOCKTIME|-] [TIME_LOCKTIME|-]");
    }
    auto psbt = Decode(argv[2]);
    const auto txid = Txid::FromHex(argv[3]);
    if (!txid) Fail("invalid txid: " + std::string{argv[3]});
    const auto sequence = argc > 5 ? OptionalNumber(argv[5], "sequence") : std::nullopt;
    PSBTInput input(psbt.GetVersion(), *txid, Number<uint32_t>(argv[4], "vout"), sequence);
    if (argc > 6) input.height_locktime = OptionalNumber(argv[6], "height locktime");
    if (argc > 7) input.time_locktime = OptionalNumber(argv[7], "time locktime");
    if (!psbt.AddInput(input)) Fail("Core rejected input");
    return Encode(psbt);
}

std::string AddOutput(int argc, char** argv)
{
    ExpectArgs(argc, 5, "add-output PSBT_BASE64 AMOUNT_SAT SCRIPT_HEX");
    auto psbt = Decode(argv[2]);
    const auto script_bytes = TryParseHex<unsigned char>(argv[4]);
    if (!script_bytes) Fail("invalid script hex: " + std::string{argv[4]});
    const CScript script(script_bytes->begin(), script_bytes->end());
    const PSBTOutput output(psbt.GetVersion(), Number<CAmount>(argv[3], "amount"), script);
    if (!psbt.AddOutput(output)) Fail("Core rejected output");
    return Encode(psbt);
}
} // namespace

int main(int argc, char** argv)
{
    try {
        ECC_Context ecc_context{};
        ExpectMinArgs(argc, 2, "COMMAND [ARG ...]");
        const std::string_view command{argv[1]};
        std::string output;
        if (command == "version") {
            ExpectArgs(argc, 2, "version");
            output = std::to_string(PSBT_HIGHEST_VERSION);
        } else if (command == "inspect") {
            ExpectArgs(argc, 3, "inspect PSBT_BASE64");
            output = Inspect(Decode(argv[2]));
        } else if (command == "roundtrip") {
            output = Roundtrip(argc, argv);
        } else if (command == "combine") {
            output = Combine(argc, argv);
        } else if (command == "finalize") {
            output = Finalize(argc, argv);
        } else if (command == "extract") {
            output = Extract(argc, argv);
        } else if (command == "sign") {
            output = Sign(argc, argv);
        } else if (command == "add-input") {
            output = AddInput(argc, argv);
        } else if (command == "add-output") {
            output = AddOutput(argc, argv);
        } else {
            Fail("unknown command: " + std::string{command});
        }
        std::cout << output << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
}
