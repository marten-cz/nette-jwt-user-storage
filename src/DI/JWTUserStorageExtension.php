<?php


namespace Marten\Nette\JwtStorage\Security\DI;

use Nette;
use Nette\DI\CompilerExtension;
use Nette\Schema\Expect;

/**
 * Nette DI extension which registers JWTUserStorage.
 * @package   Marten\Nette\JwtStorage\Security\DI
 * @author    Filip Klimes <filip@filipklimes.cz>
 */
class JWTUserStorageExtension extends CompilerExtension
{
	public function getConfigSchema(): Nette\Schema\Schema
	{
		return Expect::structure([
			'identitySerializer' => Expect::string('Marten\Nette\JwtStorage\Security\IdentitySerializer'),
			'generateJti' => Expect::bool(true),
			'generateIat' => Expect::bool(true),
			'expiration' => Expect::string('20 days'),
			'privateKey' => Expect::string()->required(),
			'algorithm' => Expect::string()->required(),
			'jwtLeeway' => Expect::int(0),
		]);
	}

	public function loadConfiguration()
	{
		$builder = $this->getContainerBuilder();
		$config = (array) $this->getConfig();

		$builder->addDefinition($this->prefix('firebaseJWTWrapper'))
			->setType('Marten\Nette\JwtStorage\Security\JWT\FirebaseJWTWrapper')
			->setArguments([isset($config['jwtLeeway']) ? ((int) $config['jwtLeeway']) : 0]);

		$userStorageDefinition = $builder->addDefinition($this->prefix('jwtUserStorage'))
			->setType('Marten\Nette\JwtStorage\Security\JWTUserStorage')
			->setArguments([$config['privateKey'], $config['algorithm']]);
		$userStorageDefinition->addSetup('setGenerateIat', [$config['generateIat']]);
		$userStorageDefinition->addSetup('setGenerateJti', [$config['generateJti']]);

		// If expiration date is set, add service setup
		if ($config['expiration']) {
			$userStorageDefinition->addSetup('setExpiration', [$config['expiration']]);
		}

		$builder->addDefinition($this->prefix('identitySerializer'))
			->setType($config['identitySerializer']);

		// Disable Nette's default IUserStorage implementation
		$builder->getDefinition('security.userStorage')->setAutowired(false);
	}
}
