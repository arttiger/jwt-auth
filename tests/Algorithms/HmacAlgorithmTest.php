<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Test\Algorithms;

use ArtTiger\JWTAuth\Algorithms\Hs256;
use ArtTiger\JWTAuth\Algorithms\Hs384;
use ArtTiger\JWTAuth\Algorithms\Hs512;
use ArtTiger\JWTAuth\Exceptions\JWTException;
use ArtTiger\JWTAuth\Test\AbstractTestCase;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Hmac\Sha384;
use Lcobucci\JWT\Signer\Hmac\Sha512;

class HmacAlgorithmTest extends AbstractTestCase
{
    // --- HS256 ---

    public function testHs256IdReturnsCorrectString(): void
    {
        $this->assertSame('HS256', (new Hs256())->id());
    }

    public function testHs256IsNotAsymmetric(): void
    {
        $this->assertFalse((new Hs256())->isAsymmetric());
    }

    public function testHs256SignerClassReturnsSha256(): void
    {
        $this->assertSame(Sha256::class, (new Hs256())->signerClass());
    }

    public function testHs256AcceptsSecretOfExactMinimumLength(): void
    {
        $secret = str_repeat('a', 32); // exactly 32 bytes

        (new Hs256())->validateKeyMaterial($secret, []);

        $this->assertTrue(true);
    }

    public function testHs256AcceptsSecretLongerThanMinimum(): void
    {
        $secret = str_repeat('a', 64);

        (new Hs256())->validateKeyMaterial($secret, []);

        $this->assertTrue(true);
    }

    public function testHs256ThrowsForNullSecret(): void
    {
        $this->expectException(JWTException::class);
        $this->expectExceptionMessage('HS256');

        (new Hs256())->validateKeyMaterial(null, []);
    }

    public function testHs256ThrowsForEmptySecret(): void
    {
        $this->expectException(JWTException::class);
        $this->expectExceptionMessage('HS256');

        (new Hs256())->validateKeyMaterial('', []);
    }

    public function testHs256ThrowsForSecretShorterThanMinimum(): void
    {
        $this->expectException(JWTException::class);
        $this->expectExceptionMessage('32 bytes');

        $secret = str_repeat('a', 16); // only 16 bytes

        (new Hs256())->validateKeyMaterial($secret, []);
    }

    public function testHs256ThrowsWithInformativeMessageForShortSecret(): void
    {
        $this->expectException(JWTException::class);
        $this->expectExceptionMessage('HS256');

        (new Hs256())->validateKeyMaterial(str_repeat('x', 10), []);
    }

    // --- HS384 ---

    public function testHs384IdReturnsCorrectString(): void
    {
        $this->assertSame('HS384', (new Hs384())->id());
    }

    public function testHs384IsNotAsymmetric(): void
    {
        $this->assertFalse((new Hs384())->isAsymmetric());
    }

    public function testHs384SignerClassReturnsSha384(): void
    {
        $this->assertSame(Sha384::class, (new Hs384())->signerClass());
    }

    public function testHs384AcceptsSecretOfExactMinimumLength(): void
    {
        $secret = str_repeat('b', 48); // exactly 48 bytes

        (new Hs384())->validateKeyMaterial($secret, []);

        $this->assertTrue(true);
    }

    public function testHs384ThrowsForNullSecret(): void
    {
        $this->expectException(JWTException::class);

        (new Hs384())->validateKeyMaterial(null, []);
    }

    public function testHs384ThrowsForEmptySecret(): void
    {
        $this->expectException(JWTException::class);

        (new Hs384())->validateKeyMaterial('', []);
    }

    public function testHs384ThrowsForSecretShorterThanMinimum(): void
    {
        $this->expectException(JWTException::class);
        $this->expectExceptionMessage('48 bytes');

        (new Hs384())->validateKeyMaterial(str_repeat('b', 32), []);
    }

    // --- HS512 ---

    public function testHs512IdReturnsCorrectString(): void
    {
        $this->assertSame('HS512', (new Hs512())->id());
    }

    public function testHs512IsNotAsymmetric(): void
    {
        $this->assertFalse((new Hs512())->isAsymmetric());
    }

    public function testHs512SignerClassReturnsSha512(): void
    {
        $this->assertSame(Sha512::class, (new Hs512())->signerClass());
    }

    public function testHs512AcceptsSecretOfExactMinimumLength(): void
    {
        $secret = str_repeat('c', 64); // exactly 64 bytes

        (new Hs512())->validateKeyMaterial($secret, []);

        $this->assertTrue(true);
    }

    public function testHs512ThrowsForNullSecret(): void
    {
        $this->expectException(JWTException::class);

        (new Hs512())->validateKeyMaterial(null, []);
    }

    public function testHs512ThrowsForEmptySecret(): void
    {
        $this->expectException(JWTException::class);

        (new Hs512())->validateKeyMaterial('', []);
    }

    public function testHs512ThrowsForSecretShorterThanMinimum(): void
    {
        $this->expectException(JWTException::class);
        $this->expectExceptionMessage('64 bytes');

        (new Hs512())->validateKeyMaterial(str_repeat('c', 48), []);
    }

    public function testHs512AcceptsLongerSecret(): void
    {
        $secret = str_repeat('z', 128);

        (new Hs512())->validateKeyMaterial($secret, []);

        $this->assertTrue(true);
    }
}
