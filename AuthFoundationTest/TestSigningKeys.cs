using AuthFoundation.Services;

namespace AuthFoundationTest;

internal static class TestSigningKeys
{
    public const string KeyId = "test-signing-key";

    public const string PrivateKeyPem = """
        -----BEGIN PRIVATE KEY-----
        MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDewialmcgRFtD9
        AbtQQlw3cmz5qeXORf3xEfhHR+BCUWMW/7r5yNFSo5BSmGUDsPCCy+b+lVIzHZCI
        /9yeVmJRh7hH/lLxPKNVfxHwCOnK2gMnBUg1zwJWMvh98EkPL2JteqlS1m/rF0aA
        SYt4lW/vqunTOo/iq5/FcnyMdDONWP4MznqXZrs26tJdSXqrNtlG5TdPBgsx+Kpx
        Ef+rvHgmkh00cnQ631iopuRtXxoftEVdn1ME49y0lJtCtQoMI51N92ZE5GarqTZo
        5DVtsDsKNgEpygK5ro4aTzPjorkqH83B/gIDKYHeTEXVlwCrNTMXaA6w5pcw/cZY
        +7253hOnAgMBAAECggEAEddZAxBzDrNWH72AxCfcfPBkPAbYihHfCezXhtYB5y3f
        ktr+nbzwzv6cs5DTHl2QldlA8gkBoWhvyBk+EUx36XHGV7XN7NZfepyH0kLUftPB
        RuHMa8rdtAu3DVcuctHnvz8Aysq0Ag9GLUY2rnzBj1+QBMP+/Dekv0qxIQq5ikt9
        DYPP/HIvoxwIcvpK4q+ABQ7ImRRICLdMo3DYJ/UrOC4mibNy4NBXXfCgKcfN3U/h
        6gLCqye9T3ejIGOD9Pvk5wB+RgM6uIjpZGmSRBOBsyMWJWKq3Nwax/xi90UzZ8lg
        p47uwJ3cRwITlazGtDr+mA88ZrDUKeBUfBMlofKzWQKBgQD/2RvG+gNgBAsGrAfb
        387ZXHWJTixG/cnmI0rAzLF66tfOxEOrND6RSLdEM4ugCRrkNIYEExA7+OSmSD9q
        DRRbXCzG8cumpif0SCERq3fWA0Azjc9Fg4btGwEugRiPqwxtus/cah+J37tpm8N7
        Ss6QxY/aPiEMqjQjhP5SE8JWbQKBgQDe5AMyzCa6xp5Eym9TWLnzHEo9fq+r3fzb
        SahxHYDDUystO3Y08ZjR/j9pGDltD4om4lkE6gDdZPmGEkb7nPBwkyf0/ax9tEUg
        gkH14dXKSycY1xlncjGYgbX0beUvWXvSTVVYAByBx4jhs0w2EwQG+xbBf4naLyum
        BvlKCnaV4wKBgQD2RJorNj6HbnzaiD7sUwr9SLVOXDPcha+Q2Ym7+Ywgv+rI+TwV
        kK1lFTRq7p7IhdsfrLsPMvZec95LfKGlyD8/DYOAYABiQe+VgNRr+LvaAbkLpsXL
        qKX4lxTVGah1qfTFrpskE/aVtQjlx+wrQj+BNNmZ/lG7qh2TzxEqGiDnJQKBgHHQ
        apWwy4IKU9z6pdggcWtjocE/BIM1ap2rQhjooMyclmqVd2nXiFqKgmSu2vwGuFvc
        ruokd2aV3hiJErf+zoQdkIS4WDEkMTxFZ1sgA6Q1tfQoOi+pjwu6CGiVCTehcOnV
        VWQHQoc+lXXysVLXaPILmvYZoxHHjnlMDFWzfBRTAoGAMFb83hfM8ih6ZXDDlbwm
        BGElBRy+ObIkCyXz/BPYStTRdFGARmCe7pP19BMQVrQNa+chKqwPUQMs0NsHOq8H
        oXCavfMO0/NRdxLAgpCW0Ex6e5xT16VC1GD9wpr/EZVJonESbRpylDNMaX4XfRjp
        7J2FO+Ol06U+QKrG3krsaUg=
        -----END PRIVATE KEY-----
        """;

    public static SigningKeyProvider Create()
    {
        return SigningKeyProvider.FromPem(KeyId, PrivateKeyPem);
    }

    public static OidcTokenService CreateTokenService(IOidcStore store)
    {
        return new OidcTokenService(store, Create());
    }
}
