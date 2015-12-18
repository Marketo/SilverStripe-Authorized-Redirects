<?php

/**
 * Description of ScheduleRangeTest
 *
 * @author Stephen McMahon <stephen@silverstripe.com.au>
 */
class AuthorizedTest extends SapphireTest {

	protected static $fixture_file = 'Authorized.yml';

	public function setUp() {
		parent::setUp();

		SS_Datetime::create()->set_mock_now('2015-01-01T00:00:00+11:00');
		$_SERVER['HTTP_USER_AGENT'] = 'A TEST STRING';
		$_SERVER['REMOTE_ADDR'] = '127.0.0.1';
	}

	public function testAbsoluteLink() {
		$auth = $this->objFromFixture('Authorization', 'Auth1');
		$expected = 'authtesturl/?Email=test%40email.com&AccessCode=1353D210FA';
		$this->assertTrue((strpos($auth->AbsoluteLink(), $expected) !== false));
	}

	public function testgetMenuTitle() {
		$auth = $this->objFromFixture('Authorization', 'Auth1');

		$this->assertEquals('test@email.com (1353D210FA on Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.73 Safari/537.36)', $auth->getMenuTitle(), $auth->getMenuTitle());
	}

	public function testEmailAuthorization() {
		$auth = $this->objFromFixture('Authorization', 'Auth1');

		$this->assertTrue($auth->EmailAuthorization());
	}

	public function testAuthorizationErrors() {
		$authPage = $this->objFromFixture('AuthorizedPage', 'AuthPage1');
		$Email = 'test@email.com';
		$AccessCode = '1353D210FA';
		$ClientKey = 'c2f2045d15a91bff866ff8f57c48f6540ff26b1c';
		$ClientInfo = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.73 Safari/537.36';

		$this->assertEquals(0, Authorization::AuthorizationErrors($authPage, $Email, $AccessCode, $ClientKey, $ClientInfo));
	}

	public function testFetch() {
		$authPage = $this->objFromFixture('AuthorizedPage', 'AuthPage1');
		$auth = $this->objFromFixture('Authorization', 'Auth1');

		$Email = 'test@email.com';
		$AccessCode = '1353D210FA';
		$ClientKey = 'c2f2045d15a91bff866ff8f57c48f6540ff26b1c';
		$ClientInfo = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.73 Safari/537.36';

		$this->assertEquals($auth, Authorization::Fetch($authPage, $Email, $AccessCode, $ClientKey, $ClientInfo));
	}

	public function testgenerateClientKey() {

		$this->assertEquals('f57fa6a129a4c369157f521724ca24bf6a8e25fc', Authorization::generateClientKey());
	}

	public function testgenerateClientInfo() {

		$this->assertEquals('A TEST STRING', Authorization::generateClientInfo());
	}

	/**********************************************/

	public function testIsAllowedEmail() {
		$authPage = $this->objFromFixture('AuthorizedPage', 'AuthPage1');
		$email = 'test@email.com';
		$this->assertTrue($authPage->IsAllowedEmail('test@email.com'), $authPage->IsAllowedEmail('test@email.com'));
	}

}
