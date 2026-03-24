<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Test\Algorithms;

use ArtTiger\JWTAuth\Algorithms\Es256;
use ArtTiger\JWTAuth\Algorithms\Es384;
use ArtTiger\JWTAuth\Algorithms\Es512;
use ArtTiger\JWTAuth\Algorithms\Rs256;
use ArtTiger\JWTAuth\Algorithms\Rs384;
use ArtTiger\JWTAuth\Algorithms\Rs512;
use ArtTiger\JWTAuth\Exceptions\JWTException;
use ArtTiger\JWTAuth\Test\AbstractTestCase;
use Lcobucci\JWT\Signer\Ecdsa\Sha256 as EcdsaSha256;
use Lcobucci\JWT\Signer\Ecdsa\Sha384 as EcdsaSha384;
use Lcobucci\JWT\Signer\Ecdsa\Sha512 as EcdsaSha512;
use Lcobucci\JWT\Signer\Rsa\Sha256 as RsaSha256;
use Lcobucci\JWT\Signer\Rsa\Sha384 as RsaSha384;
use Lcobucci\JWT\Signer\Rsa\Sha512 as RsaSha512;

/**
 * Unparseable strings are intentionally used for key material in most tests.
 * When openssl cannot parse the string, RsaAlgorithm and EcdsaAlgorithm skip
 * the bit-length check — so validation passes as long as a key string is present.
 */
class AsymmetricAlgorithmTest extends AbstractTestCase
{
    // Non-PEM strings that openssl cannot parse → key length check is skipped
    private const UNPARSEABLE_KEY = 'not-a-real-pem-key';

    // --- RS256 ---

    public function testRs256IdReturnsCorrectString(): void
    {
        $this->assertSame('RS256', (new Rs256())->id());
    }

    public function testRs256IsAsymmetric(): void
    {
        $this->assertTrue((new Rs256())->isAsymmetric());
    }

    public function testRs256SignerClassIsCorrect(): void
    {
        $this->assertSame(RsaSha256::class, (new Rs256())->signerClass());
    }

    public function testRs256ThrowsWhenNoKeysProvided(): void
    {
        $this->expectException(JWTException::class);
        $this->expectExceptionMessage('RS256');

        (new Rs256())->validateKeyMaterial(null, []);
    }

    public function testRs256PassesWithUnparseableKeys(): void
    {
        // openssl cannot parse → bit-length check skipped → no exception
        (new Rs256())->validateKeyMaterial(null, [
            'public' => self::UNPARSEABLE_KEY,
            'private' => self::UNPARSEABLE_KEY,
        ]);

        $this->assertTrue(true);
    }

    public function testRs256PassesWithOnlyPublicKey(): void
    {
        (new Rs256())->validateKeyMaterial(null, [
            'public' => self::UNPARSEABLE_KEY,
        ]);

        $this->assertTrue(true);
    }

    public function testRs256ThrowsWhenBothKeysAreNull(): void
    {
        $this->expectException(JWTException::class);

        (new Rs256())->validateKeyMaterial(null, ['public' => null, 'private' => null]);
    }

    // --- RS384 ---

    public function testRs384IdReturnsCorrectString(): void
    {
        $this->assertSame('RS384', (new Rs384())->id());
    }

    public function testRs384IsAsymmetric(): void
    {
        $this->assertTrue((new Rs384())->isAsymmetric());
    }

    public function testRs384SignerClassIsCorrect(): void
    {
        $this->assertSame(RsaSha384::class, (new Rs384())->signerClass());
    }

    public function testRs384ThrowsWhenNoKeysProvided(): void
    {
        $this->expectException(JWTException::class);

        (new Rs384())->validateKeyMaterial(null, []);
    }

    public function testRs384PassesWithUnparseableKeys(): void
    {
        (new Rs384())->validateKeyMaterial(null, [
            'public' => self::UNPARSEABLE_KEY,
            'private' => self::UNPARSEABLE_KEY,
        ]);

        $this->assertTrue(true);
    }

    // --- RS512 ---

    public function testRs512IdReturnsCorrectString(): void
    {
        $this->assertSame('RS512', (new Rs512())->id());
    }

    public function testRs512IsAsymmetric(): void
    {
        $this->assertTrue((new Rs512())->isAsymmetric());
    }

    public function testRs512SignerClassIsCorrect(): void
    {
        $this->assertSame(RsaSha512::class, (new Rs512())->signerClass());
    }

    public function testRs512ThrowsWhenNoKeysProvided(): void
    {
        $this->expectException(JWTException::class);

        (new Rs512())->validateKeyMaterial(null, []);
    }

    public function testRs512PassesWithUnparseableKeys(): void
    {
        (new Rs512())->validateKeyMaterial(null, [
            'public' => self::UNPARSEABLE_KEY,
            'private' => self::UNPARSEABLE_KEY,
        ]);

        $this->assertTrue(true);
    }

    // --- ES256 ---

    public function testEs256IdReturnsCorrectString(): void
    {
        $this->assertSame('ES256', (new Es256())->id());
    }

    public function testEs256IsAsymmetric(): void
    {
        $this->assertTrue((new Es256())->isAsymmetric());
    }

    public function testEs256SignerClassIsCorrect(): void
    {
        $this->assertSame(EcdsaSha256::class, (new Es256())->signerClass());
    }

    public function testEs256ThrowsWhenNoKeysProvided(): void
    {
        $this->expectException(JWTException::class);
        $this->expectExceptionMessage('ES256');

        (new Es256())->validateKeyMaterial(null, []);
    }

    public function testEs256PassesWithUnparseableKeys(): void
    {
        (new Es256())->validateKeyMaterial(null, [
            'public' => self::UNPARSEABLE_KEY,
            'private' => self::UNPARSEABLE_KEY,
        ]);

        $this->assertTrue(true);
    }

    public function testEs256PassesWithOnlyPublicKey(): void
    {
        (new Es256())->validateKeyMaterial(null, [
            'public' => self::UNPARSEABLE_KEY,
        ]);

        $this->assertTrue(true);
    }

    // --- ES384 ---

    public function testEs384IdReturnsCorrectString(): void
    {
        $this->assertSame('ES384', (new Es384())->id());
    }

    public function testEs384IsAsymmetric(): void
    {
        $this->assertTrue((new Es384())->isAsymmetric());
    }

    public function testEs384SignerClassIsCorrect(): void
    {
        $this->assertSame(EcdsaSha384::class, (new Es384())->signerClass());
    }

    public function testEs384ThrowsWhenNoKeysProvided(): void
    {
        $this->expectException(JWTException::class);

        (new Es384())->validateKeyMaterial(null, []);
    }

    public function testEs384PassesWithUnparseableKeys(): void
    {
        (new Es384())->validateKeyMaterial(null, [
            'public' => self::UNPARSEABLE_KEY,
            'private' => self::UNPARSEABLE_KEY,
        ]);

        $this->assertTrue(true);
    }

    // --- ES512 ---

    public function testEs512IdReturnsCorrectString(): void
    {
        $this->assertSame('ES512', (new Es512())->id());
    }

    public function testEs512IsAsymmetric(): void
    {
        $this->assertTrue((new Es512())->isAsymmetric());
    }

    public function testEs512SignerClassIsCorrect(): void
    {
        $this->assertSame(EcdsaSha512::class, (new Es512())->signerClass());
    }

    public function testEs512ThrowsWhenNoKeysProvided(): void
    {
        $this->expectException(JWTException::class);

        (new Es512())->validateKeyMaterial(null, []);
    }

    public function testEs512PassesWithUnparseableKeys(): void
    {
        (new Es512())->validateKeyMaterial(null, [
            'public' => self::UNPARSEABLE_KEY,
            'private' => self::UNPARSEABLE_KEY,
        ]);

        $this->assertTrue(true);
    }
}
