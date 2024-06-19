# json-web-key-generator

A commandline Java-based generator for JSON Web Keys (JWK) and JSON Private/Shared Keys (JPSKs).

## Standalone run

To compile, run `mvn package`. This will generate a `json-web-key-generator-jar-with-dependencies.jar` in the `/target` directory.

To generate a key, run `java -jar target/json-web-key-generator-jar-with-dependencies.jar -t <keytype>`. Several other arguments are defined which may be required depending on your key type:

```
usage: java -jar json-web-key-generator.jar -t <keyType> [options]
 -t,--type <arg>           Key Type, one of: RSA, oct, EC, OKP
                           (case-insensitive)
 -s,--size <arg>           Key Size in bits, required for RSA and oct key
                           types. Must be an integer divisible by 8. If
                           omitted, defaults to 2048 for RSA, 2048 for oct
 -c,--curve <arg>          Key Curve, required for EC or OKP key type.
                           Must be one of P-256, secp256k1, P-384, P-521
                           for EC keys or one of Ed25519, Ed448, X25519,
                           X448 for OKP keys. If omitted, defaults to
                           P-256 for EC, Ed25519 for OKP
 -u,--usage <arg>          Usage, one of: enc, sig (optional)
 -a,--algorithm <arg>      Algorithm (optional)
 -i,--id <arg>             Key ID (optional), one will be generated if not
                           defined
 -g,--idGenerator <arg>    Key ID generation method (optional). Can be one
                           of: date, timestamp, sha256, sha384, sha512,
                           uuidv1, uuidv4, uuidv6, uuidv7, none. If
                           omitted, generator method defaults to
                           'timestamp'.
 -I,--noGenerateId         <deprecated> Don't generate a Key ID.
                           (Deprecated, use '-g none' instead.)
 -p,--showPubKey           Display public key separately (if applicable)
 -S,--keySet               Wrap the generated key in a KeySet
 -o,--output <arg>         Write output to file. Will append to existing
                           KeySet if -S is used. Key material will not be
                           displayed to console.
 -P,--pubKeyOutput <arg>   Write public key to separate file. Will append
                           to existing KeySet if -S is used. Key material
                           will not be displayed to console. '-o/--output'
                           must be declared as well.
 -x,--x509                 Display keys in X509 PEM format
 -C,--compact              Write output in compact mode.
```

## Docker

### Build with docker
Example:


```bash
# Optional TAG
#TAG="your/tag:here"
# Example: TAG="<your_docker_id>/json-web-key-generator:latest"
$ docker build -t $TAG .
```

If building from git tags then run the following to store the *tag*, and the *commit*
in the docker image label.

```bash
TAG=$(git describe --abbrev=0 --tags)
REV=$(git log -1 --format=%h)
docker build -t <your_docker_id>/json-web-key-generator:$TAG --build-arg GIT_COMMIT=$REV --build-arg GIT_TAG=$TAG .
docker push <your_docker_id>/json-web-key-generator:$TAG

# or push all the tags
docker push <your_docker_id>/json-web-key-generator --all-tags
```

### Run from docker

Example of running the app  within a docker container to generate a 3072 bit RSA JWK, kid generator = uuid.

```bash
$ docker run --rm <your_docker_id>/json-web-key-generator:latest -t RSA -s 3072 -g uuid
Full key:
{
  "p": "9Y-Qn4lqZogfG-9-Xb5oFvW8DIL299gMvmxIuvv9GBXQSSVlTD7w_DAYkGeRRfqojpUzLXJd4f654WQwASaKRng--P2Z58S3Jyaic1rUA7de_9qBcQ8_0gp2LuEZQV5wPl0jWbtbzdS37ZW24L_SdbZDi-7VwG7keM8yp01z9D7s9h0y5nD8GkS2vq6aPZlqHqDRjIJ5BunxFuRfg4aRTYUiPw0S0L2qiP91OqwLG3qiOcwZTt1VZ53-9ToqaqFD",
  "kty": "RSA",
  "q": "_krVVmNMKd6Enigkywj_wxHZXuobhk22ou9q9NN363ri7GND005gBNdjoEyv-cP7KxwzSFPxiuZ7k6pifd85iy6ue1_MOp7oM4B7y3SyfQB9dKZDintHYUxKOkX-Fo6FxWDIWJnLcoMz0mXOax7ZkPIQS3wHmpOOTqoL6DcnNoz8vhmqCxxzmcguQdNk9r-7hduHImyjmdtvKnQjwj9atH8MroRpOaJETnMzU0ln9uL2G5Z9EGIJ4HhOhygHDKHX",
  "d": "BK9taKB31a-8vdKgVTue9xcXGwcZBEEUbMDCQHYCYzfxG2jR-k_7mO9TC0-_ZE3YNhCyo-Pjb3YeikTPlC0Rz8fQwyqBhASQmhWcdLOZrhyt6M2mczR-RQIRT8Jeisx8vASlvkimiKyGtIsWnioMUobAVbokynbPuI3HIIaEYR3yGD4uz9dorfiCZvSYVD_gdS9bMZrFslKcTS6O-EW9Z_4_Zc165o1FXj3h9XgJTlgIFOIdwgXP7YurNGQ5_MaY7j2ovDfpCqADhPL-d3O4FGqXC8vMyxzGg3rWO3ruDpkKVDt2h7-ahRbhJpIZLwtXWCb2U1Kve1fcfABIwm_7p6bnN6f4MjnhQS71FB4zTuB_zHw8-U7YktYd9WrrTDJLK7Z6Hj70HT6rHbUEAIsbXJZAy9Djmh1uxeenaFc4Uc--v5iooRCToS2kBgwvHdRkzRLsnh39XyMLQJu1dx4y2er9Mc2QgkFkZumvn1a2jMs9W45haFMFEuWL1P3CLdAz",
  "e": "AQAB",
  "kid": "ee26cb95-e7e8-442f-8b92-e6f77fa29067",
  "qi": "GN7EAfHsvdQCtJ3ZZfzNG5MWlsnoihYbo_yLI2KjArflcRFdRUo3AHSdcvaAKAmJIIZYR357lTmPCGGT9JgPqsQAPn-8-7QPf76hdzOGhuttHf4OmwKkPsYUhSrocC3tf9vj6Qp_DPLvwIhcxh18hujTRcVv08GrVrSbT_sjb0Xt55CawJ5_hvXOn9ELjhcTHLVyJu9vLd8AnEv1KMMHZohj26IaXi3HTs-dYwNMEh68J62Qaca_lvih4IY8p1Br",
  "dp": "YO6w-ij2VU76aL6bNUoKMLYD6zRvZNpl_W0lMJp0B-PkeltGp1hZLFOX_rjDQcp2awI-V3xDzwgMPAqeYHXkM3kX8pW5ASJH4i6ABeUet_DUkU6htg189d6nVE4K-CDdUeDWKX-p95A2opRswj82Rr0R4NUAj5u2mHHB3wTV9t44D9bq1shW28-wC4lE3XgHydtVnI-MUsxaHN09Tt_5z430PMteWAPmo3mjvutW3xwDmakVfGomYmad1BOH1tud",
  "dq": "6h-WCeKEdiwUJ9VIAtM3P6-IVZXvX5jfZWZPMDgeueS7Vu8RvFP1nZ99b1IL10a0Un21TYtT4RHRhyQhaEiEn3uMU7TgwLwbh4ds8uZvix1PZH3Lw407K_7kfICCrtvrl81CyChZIwZfSQBIq2GM6KGllQoNqijepdhz_AoDhXsLHC9e2roISPcAd8ScuX3Pti9nXK9vdTGOSSUC404XQgWTdH4er1yRzTTNdYopOSq_cqj8XoAVHeFGU7PrwZqj",
  "n": "8-w5oWlEMSB0pA2W1S7HpMTlJW0c-6W1mlsbiFcTiQgqtblO9zanAxGE0thRWw2PhZ_z6vUvsSPk1AsWD-0nDJEKVXeL6yNGH23S_B0XOf9k7qiSUvXk_KUyF__s_GEcz5NbDwb6m-x8ij6rJblCyTVsHeyDxGbNvfDRhoUdlSo9qEV-U8M7j5QobZyuYs72wnHkeGJJGCk0zFnq0NzJaRok0aRtJQNW1qqpimMyAL8csNSTq3L93qJeTgsgXnq2GWROr0BzKA2YkX2BSdRKslcxTtstdFUSGYpqtcZY40AV7fEStitiS5M-hvsLA5aWm2ubuzmt01MOuPeLJwQFblIzSbJXOhit6E3lJktbvppgGHR1LApZ_Uh5emE6ndVPXCrA1Raf63aIWRLh1qc8fKpNr9VO9-k-Ez7OpGN9lZNBL4BJ_dR7wOrN9WYiul3RLCyzdZuHAzcikMj0Go7Wk6jUFYxCsICJdZ1FJiR4sxTJvju0LCegNIVZ92cTHJJF"
}
```

## Verify the GPG Signature of release JAR

### Import the public key
```bash
gpg --import gpg\0xBA26C1D5_public.asc
```

### Verify the signature
```bash
gpg --verify json-web-key-generator.jar.asc json-web-key-generator.jar
```
