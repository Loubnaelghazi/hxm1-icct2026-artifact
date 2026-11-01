"""
Benchmark OpenSSL CMS (RSA-OAEP + AES-256-GCM... note: OpenSSL CMS uses
CBC or GCM depending on version/cipher choice -- we use -aes256 which is
CBC by default in classic CMS; see note below) to compare package overhead
and enc/dec timing against HXM1, using the SAME methodology as Table 4
of the paper: 30 iterations per payload size, median +/- sample stdev.

Run from inside openssl_cms_bench/, where cert.pem and rsa_priv.pem
already exist

  
"""
import os
import statistics
import subprocess
import time

N_ITERATIONS = 30
SIZES = {
    "128B": 128,
    "16KiB": 16384,
    "1MiB": 1024 * 1024,
}

CERT = "cert.pem"
PRIV = "rsa_priv.pem"


def run(cmd: list[str]) -> None:
    subprocess.run(cmd, check=True, capture_output=True)


def bench_size(label: str, size: int) -> dict:
    plain_path = f"bench_{label}.bin"
    cms_path = f"bench_{label}.cms"
    dec_path = f"bench_{label}.dec"

    with open(plain_path, "wb") as f:
        f.write(os.urandom(size))

    enc_times = []
    dec_times = []
    overhead = None

    for _ in range(N_ITERATIONS):
        t0 = time.perf_counter()
        run([
            "openssl", "cms", "-encrypt", "-in", plain_path, "-out", cms_path,
            "-recip", CERT, "-aes256", "-binary", "-outform", "DER",
            "-keyopt", "rsa_padding_mode:oaep",
        ])
        enc_times.append((time.perf_counter() - t0) * 1000)  # ms

        if overhead is None:
            overhead = os.path.getsize(cms_path) - size

        t0 = time.perf_counter()
        run([
            "openssl", "cms", "-decrypt", "-in", cms_path, "-out", dec_path,
            "-recip", CERT, "-inkey", PRIV, "-binary", "-inform", "DER",
            "-keyopt", "rsa_padding_mode:oaep",
        ])
        dec_times.append((time.perf_counter() - t0) * 1000)  # ms

    # sanity check on the last iteration
    with open(plain_path, "rb") as f1, open(dec_path, "rb") as f2:
        assert f1.read() == f2.read(), f"round-trip mismatch for {label}!"

    for p in (plain_path, cms_path, dec_path):
        os.remove(p)

    return {
        "label": label,
        "size": size,
        "overhead_bytes": overhead,
        "enc_ms_median": statistics.median(enc_times),
        "enc_ms_stdev": statistics.stdev(enc_times),
        "dec_ms_median": statistics.median(dec_times),
        "dec_ms_stdev": statistics.stdev(dec_times),
    }


def main():
    print(f"OpenSSL CMS benchmark -- {N_ITERATIONS} iterations per size\n")
    results = []
    for label, size in SIZES.items():
        print(f"Running {label}...")
        r = bench_size(label, size)
        results.append(r)

    print("\n" + "=" * 70)
    print(f"{'Size':<8}{'Overhead(B)':<14}{'Enc ms (median±stdev)':<26}{'Dec ms (median±stdev)'}")
    print("=" * 70)
    for r in results:
        enc = f"{r['enc_ms_median']:.3f}±{r['enc_ms_stdev']:.3f}"
        dec = f"{r['dec_ms_median']:.3f}±{r['dec_ms_stdev']:.3f}"
        print(f"{r['label']:<8}{r['overhead_bytes']:<14}{enc:<26}{dec}")

    print("\nLaTeX row (16KiB, to match Table 4 format):")
    r16 = next(r for r in results if r["label"] == "16KiB")
    print(f"OpenSSL CMS (RSA-3072) & {r16['overhead_bytes']} & "
          f"{r16['enc_ms_median']:.3f}$\\pm${r16['enc_ms_stdev']:.3f} & "
          f"{r16['dec_ms_median']:.3f}$\\pm${r16['dec_ms_stdev']:.3f} \\\\")


if __name__ == "__main__":
    main()