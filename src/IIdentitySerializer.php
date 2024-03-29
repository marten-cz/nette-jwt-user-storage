<?php

declare(strict_types=1);

namespace Marten\Nette\JwtStorage;

use Nette\Security\IIdentity;

/**
 * Interface for IIdentity serializer used to serialize your implementation
 * of Nette\Security\IIdentity and store the data in the JWT access token.
 * @package   Marten\Nette\JwtStorage
 * @author    Filip Klimes <filip@filipklimes.cz>
 */
interface IIdentitySerializer
{

	/**
	 * Serializes the IIdentity into an array, which will then be stored in
	 * the JWT access token.
	 * @param IIdentity $identity
	 * @return array
	 */
	public function serialize(IIdentity $identity): array;

	/**
	 * Deserializes the identity data from an array contained in the JWT and
	 * loads into into IIdentity.
	 * @param array $jwtData
	 * @return IIdentity|null
	 */
	public function deserialize($jwtData): ?IIdentity;

}
