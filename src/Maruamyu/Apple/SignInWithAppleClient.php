<?php

namespace Maruamyu\Apple;

use Maruamyu\Core\OAuth2\AccessToken;
use Maruamyu\Core\OAuth2\Client as OpenIDClient;
use Maruamyu\Core\OAuth2\JsonWebKey;
use Maruamyu\Core\OAuth2\JsonWebToken;
use Maruamyu\Core\OAuth2\OpenIDProviderMetadata;
use Psr\Http\Message\UriInterface;

/**
 * Sign in with Apple Client
 *
 * usage:
 *   0) generate secret key on developer site
 *   1) create random `state` value, and call "Sign In with Apple JS"
 *   2) take `code` and `state` from callback QUERY_STRING parameter
 *   3) $secretKeyJwk = JsonWebKey::createFromEcdsaPrivateKey('secret key PEM (EC private key)', 'passphrase', 'SECRETKEYID', 'ES256');
 *      $client = new SignInWithAppleClient('TEAMID', 'app.bundle.id', $secretKeyJwk);
 *      $accessToken = $client->generateAccessToken($code, $redirectUrl);
 *   4) save $accessToken to persistence storage
 */
class SignInWithAppleClient
{
    const ISSUER = 'https://appleid.apple.com';

    const EXPIRE_IN_MAX = 15777000;  # 6 months in seconds

    /** @var string */
    private $teamId;

    /** @var string */
    private $appBundleId;

    /** @var JsonWebKey */
    private $secretKey;

    /** @var AccessToken */
    private $accessToken;

    /**
     * @param string $teamId
     * @param string $appBundleId
     * @param JsonWebKey $secretKey
     * @param AccessToken $accessToken
     */
    public function __construct($teamId, $appBundleId, JsonWebKey $secretKey, AccessToken $accessToken = null)
    {
        $this->teamId = $teamId;
        $this->appBundleId = $appBundleId;
        $this->secretKey = $secretKey;
        $this->accessToken = $accessToken;
        $this->accessTokenExpireIn = static::EXPIRE_IN_MAX;
    }

    /**
     * @param integer $expireIn
     * @throws \Exception if less than 1 or greater than EXPIRE_IN_MAX
     */
    public function setAccessTokenExpireIn($expireIn)
    {
        if (($expireIn < 1) || ($expireIn > static::EXPIRE_IN_MAX)) {
            throw new \DomainException('invalid expire_in. (must in 1..' . static::EXPIRE_IN_MAX . ')');
        }
        $this->accessTokenExpireIn = $expireIn;
    }

    /**
     * get holding AccessToken
     *
     * @return AccessToken|null
     */
    public function getAccessToken()
    {
        if ($this->accessToken) {
            return clone $this->accessToken;
        } else {
            return null;
        }
    }

    /**
     * exchange code to access_token
     *
     * @note update holding AccessToken if succeeded
     * @param string $code
     * @param string|UriInterface $redirectUrl
     * @return AccessToken|null
     * @throws \Exception if invalid settings or arguments
     */
    public function generateAccessToken($code, $redirectUrl)
    {
        $openIDClient = $this->getOpenIDClient();
        $accessToken = $openIDClient->finishAuthorizationCodeGrant($code, $redirectUrl);
        if ($accessToken) {
            $this->accessToken = $accessToken;
        }
        return $accessToken;
    }

    /**
     * refresh access_token by refresh_token
     *
     * @return AccessToken|null
     * @throws \Exception if invalid settings or not has refresh_token
     */
    public function refreshAccessToken()
    {
        $openIDClient = $this->getOpenIDClient();
        $accessToken = $openIDClient->refreshAccessToken();
        if ($accessToken) {
            $this->accessToken = $accessToken;
        }
        return $accessToken;
    }

    /**
     * @return JsonWebKey[]
     * @throws \Exception if failed
     */
    public function fetchJwks()
    {
        return $this->getOpenIDClient()->fetchJwks();
    }

    /**
     * @return OpenIDClient
     * @throws \Exception if failed
     */
    private function getOpenIDClient()
    {
        $metadata = new OpenIDProviderMetadata();
        $metadata->issuer = static::ISSUER;
        # $metadata->authorizationEndpoint = 'https://appleid.apple.com/auth/authorize';
        $metadata->tokenEndpoint = 'https://appleid.apple.com/auth/token';
        $metadata->jwksUri = 'https://appleid.apple.com/auth/keys';
        $metadata->supportedTokenEndpointAuthMethods = ['client_secret_post'];

        # `client_secret` is dynamic value
        $clientSecret = $this->buildClientSecretJwt();

        return new OpenIDClient($metadata, $this->appBundleId, $clientSecret, $this->accessToken);
    }

    /**
     * @return string
     * @throws \Exception if failed
     */
    private function buildClientSecretJwt()
    {
        $currentTimestamp = time();
        $payload = [
            'iss' => $this->teamId,
            'iat' => $currentTimestamp,
            'exp' => ($currentTimestamp + $this->accessTokenExpireIn),
            'aud' => static::ISSUER,
            'sub' => $this->appBundleId,
        ];
        return JsonWebToken::build($payload, $this->secretKey);
    }
}
