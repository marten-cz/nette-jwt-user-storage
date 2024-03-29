<?php


namespace Marten\Nette\JwtStorage\JWT;

use DomainException;
use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Firebase\JWT\SignatureInvalidException;
use UnexpectedValueException;

/**
 * Wraps statis Firebase's JWT implementation.
 * @package   Marten\Nette\JwtStorage\JWT
 * @author    Filip Klimes <filip@filipklimes.cz>
 */
class FirebaseJWTWrapper implements IJsonWebTokenService
{
	/**
	 * @var int
	 */
	private $leeway;

	public function __construct(int $leeway = 0)
	{
		$this->leeway = $leeway;
	}

	/**
	 * Converts and signs a PHP object or array into a JWT string.
	 * @param object|array $payload     PHP object or array
	 * @param string       $key         The secret key.
	 *                                  If the algorithm used is asymmetric, this is the private key
	 * @param string       $alg         The signing algorithm.
	 *                                  Supported algorithms are 'HS256', 'HS384', 'HS512' and 'RS256'
	 * @param mixed        $keyId
	 * @param array        $head        An array with header elements to attach
	 * @return string A signed JWT
	 * @uses jsonEncode
	 * @uses urlsafeB64Encode
	 */
	function encode($payload, string $key, string $alg = 'HS256', $keyId = null, ?array $head = null): string
	{
		return JWT::encode($payload, $key, $alg, $keyId, $head);
	}

	/**
	 * Decodes a JWT string into a PHP object.
	 * @param string            $jwt            The JWT
	 * @param string|array      $key            The key, or map of keys.
	 *                                          If the algorithm used is asymmetric, this is the public key
	 * @param array             $allowed_algs   List of supported verification algorithms
	 *                                          Supported algorithms are 'HS256', 'HS384', 'HS512' and 'RS256'
	 * @return object The JWT's payload as a PHP object
	 * @throws DomainException              Algorithm was not provided
	 * @throws UnexpectedValueException     Provided JWT was invalid
	 * @throws SignatureInvalidException    Provided JWT was invalid because the signature verification failed
	 * @throws BeforeValidException         Provided JWT is trying to be used before it's eligible as defined by 'nbf'
	 * @throws BeforeValidException         Provided JWT is trying to be used before it's been created as defined by 'iat'
	 * @throws ExpiredException             Provided JWT has since expired, as defined by the 'exp' claim
	 * @uses jsonDecode
	 * @uses urlsafeB64Decode
	 */
	function decode(string $jwt, $key, array $allowed_algs = array()): object
	{
		$leeway = JWT::$leeway;
		JWT::$leeway = $this->leeway;
		try {
			return JWT::decode($jwt, $key, $allowed_algs);
		} finally {
			JWT::$leeway = $leeway;
		}
	}
}
