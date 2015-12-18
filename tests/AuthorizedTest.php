<?php

/**
 * Description of ScheduleRangeTest
 *
 * @author Stephen McMahon <stephen@silverstripe.com.au>
 */
class AuthorizedTest extends SapphireTest
{

    public static $fixture_file = 'authorized-redirects/tests/Authorized.yml';

    public function setUp()
    {
        parent::setUp();

        $_SERVER['HTTP_USER_AGENT'] = 'A TEST STRING';
        $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
    }

    public function testAbsoluteLink()
    {
        $auth = $this->objFromFixture('Authorization', 'Auth1');

        $this->assertEquals('http://ssbase.dev/authtesturl/?Email=test%40email.com&AccessCode=1353D210FA', $auth->AbsoluteLink(), $auth->AbsoluteLink());
    }

    public function testgetMenuTitle()
    {
        $auth = $this->objFromFixture('Authorization', 'Auth1');

        $this->assertEquals('test@email.com (1353D210FA on Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.73 Safari/537.36)', $auth->getMenuTitle(), $auth->getMenuTitle());
    }

    public function testEmailAuthorization()
    {
        $auth = $this->objFromFixture('Authorization', 'Auth1');

        $this->assertTrue($auth->EmailAuthorization());
    }

    public function testAuthorizationErrors()
    {
        $authPage = $this->objFromFixture('AuthorizedPage', 'AuthPage1');
        $Email = 'test@email.com';
        $AccessCode = '1353D210FA';
        $ClientKey = '7737fba2af70ce991edc9cabbb7d341aa45c81dd';
        $ClientInfo = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.73 Safari/537.36';

        $this->assertEquals(0, Authorization::AuthorizationErrors($authPage, $Email, $AccessCode, $ClientKey, $ClientInfo));
    }

    public function testFetch()
    {
        $authPage = $this->objFromFixture('AuthorizedPage', 'AuthPage1');
        $auth = $this->objFromFixture('Authorization', 'Auth1');

        $Email = 'test@email.com';
        $AccessCode = '1353D210FA';
        $ClientKey = '7737fba2af70ce991edc9cabbb7d341aa45c81dd';
        $ClientInfo = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.73 Safari/537.36';

        $this->assertEquals($auth, Authorization::Fetch($authPage, $Email, $AccessCode, $ClientKey, $ClientInfo));
    }

    public function testgenerateClientKey()
    {
        $this->assertEquals('4c43bb699d00f1bb635ccaabd6f0894c6cddf80b', Authorization::generateClientKey());
    }

    public function testgenerateClientInfo()
    {
        $this->assertEquals('A TEST STRING', Authorization::generateClientInfo());
    }

    /**********************************************/

    public function testIsAllowedEmail()
    {
        $authPage = $this->objFromFixture('AuthorizedPage', 'AuthPage1');
        $email = 'test@email.com';
        $this->assertTrue($authPage->IsAllowedEmail('test@email.com'), $authPage->IsAllowedEmail('test@email.com'));
    }
}
