<?php

declare(strict_types=1);

namespace ArtTiger\JWTAuth\Console;

use ArtTiger\JWTAuth\Traits\EnvHelperTrait;
use Illuminate\Console\Command;

class JWTGenerateCertCommand extends Command
{
    use EnvHelperTrait;

    /**
     * @var string
     */
    protected $signature = 'jwt:generate-certs
        {--force : Override certificates if existing}
        {--algo= : Algorithm (rsa/ec)}
        {--bits= : RSA-Key length (1024,2048,4096,8192}
        {--sha= : SHA-variant (1,224,256,384,512)}
        {--dir= : Directory where the certificates should be placed}
        {--curve= : EC-Curvename (e.g. secp384r1, prime256v1 )}
        {--passphrase= : Passphrase}
        {--ask-passphrase : Enter passphrase instead passing as argument}';

    /**
     * @var string
     */
    protected $description = 'Generates a new cert pair';

    public function handle(): int
    {
        $force = (bool) $this->option('force');

        $dirOption = $this->option('dir');
        $directory = is_string($dirOption) && $dirOption !== '' ? $dirOption : 'storage/certs';

        $algoOption = $this->option('algo');
        $algo = is_string($algoOption) && $algoOption !== '' ? $algoOption : 'rsa';

        $bitsOption = $this->option('bits');
        $bits = is_numeric($bitsOption) ? (int) $bitsOption : 4096;

        $shaOption = $this->option('sha');
        $shaVariant = is_numeric($shaOption) ? (int) $shaOption : 512;

        $curveOption = $this->option('curve');
        $curve = is_string($curveOption) && $curveOption !== '' ? $curveOption : 'prime256v1';

        if ($this->option('ask-passphrase')) {
            $secretInput = $this->secret('Passphrase');
            $passphrase = is_string($secretInput) ? $secretInput : null;
        } else {
            $passphraseOption = $this->option('passphrase');
            $passphrase = is_string($passphraseOption) ? $passphraseOption : null;
        }

        $filenamePublic = sprintf('%s/jwt-%s-%d-public.pem', $directory, $algo, $bits);
        $filenamePrivate = sprintf('%s/jwt-%s-%d-private.pem', $directory, $algo, $bits);

        if (file_exists($filenamePrivate)) {
            $this->warn('Private cert already exists');

            if (! $force) {
                $this->warn('Aborting');

                return self::FAILURE;
            }
        }

        if (file_exists($filenamePublic)) {
            $this->warn('Public cert already exists');

            if (! $force) {
                $this->warn('Aborting');

                return self::FAILURE;
            }
        }

        switch ($algo) {
            case 'rsa':
                $keyType = OPENSSL_KEYTYPE_RSA;
                $algoIdentifier = sprintf('RS%d', $shaVariant);
                break;

            case 'ec':
                $keyType = OPENSSL_KEYTYPE_EC;
                $algoIdentifier = sprintf('ES%d', $shaVariant);
                break;

            default:
                $this->error('Unknown algorithm');

                return self::FAILURE;
        }

        $res = openssl_pkey_new([
            'digest_alg' => sprintf('sha%d', $shaVariant),
            'private_key_bits' => $bits,
            'private_key_type' => $keyType,
            'curve_name' => $curve,
        ]);

        if ($res === false) {
            $this->error('Failed to generate key pair: '.openssl_error_string());

            return self::FAILURE;
        }

        $privKey = '';
        openssl_pkey_export($res, $privKey, $passphrase);

        $details = openssl_pkey_get_details($res);
        if ($details === false) {
            $this->error('Failed to extract public key details.');

            return self::FAILURE;
        }

        $rawKey = $details['key'];
        if (! is_string($rawKey)) {
            $this->error('Failed to extract public key string.');

            return self::FAILURE;
        }

        $pubKey = $rawKey;

        if (! is_dir($directory)) {
            mkdir($directory, 0777, true);
        }

        file_put_contents($filenamePrivate, $privKey);
        file_put_contents($filenamePublic, $pubKey);

        if (! $this->envFileExists()) {
            $this->error('.env file missing');

            return self::FAILURE;
        }

        $this->updateEnvEntry('JWT_ALGO', $algoIdentifier);
        $this->updateEnvEntry('JWT_PRIVATE_KEY', sprintf('file://../%s', $filenamePrivate));
        $this->updateEnvEntry('JWT_PUBLIC_KEY', sprintf('file://../%s', $filenamePublic));
        $this->updateEnvEntry('JWT_PASSPHRASE', $passphrase ?? '');

        return self::SUCCESS;
    }
}
