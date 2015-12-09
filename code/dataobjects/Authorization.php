<?php

class Authorization extends DataObject {

	private static $db = array(
		'Email'			=> 'Varchar(256)', // See RFC 5321, Section 4.5.3.1.3.
		'ClientInfo'	=> 'Varchar(255)',
		'ClientKey'		=> 'Varchar(40)',
		'AccessCode'	=> 'Varchar',
		'OneTimeCode'	=> 'Varchar',
		'EmailSent'		=> 'SS_Datetime',
	);

	private static $has_one = array(
		'Page' => 'AuthorizedPage'
	);


	private static $has_many = array(
	);

	static $default_sort = 'Email ASC';

	private static $summary_fields = array(
		'Page.Title'	=> 'Page Title',
		'Email'			=> 'Email',
		'AccessCode'	=> 'Access Code',
		'ClientInfo'	=> 'Client Info',
		'EmailSent'		=> 'Email Sent',
	);

	function setEmail($value) {
		$this->setField('Email',strtolower($value));
	}

	function setAccessCode($value) {
		$this->setField('AccessCode',strtoupper($value));
	}

	function AbsoluteLink() {
		if (!$this->Page()) return '';
		return str_replace('https://','http://',$this->Page()->AbsoluteLink()).'?Email='.rawurlencode($this->Email).'&AccessCode='.$this->AccessCode;
	}

	function onBeforeWrite() {
		if (!$this->ClientKey) {
			$this->ClientKey = static::generateClientKey();
		}
		if (!$this->ClientInfo) {
			$this->ClientInfo = static::generateClientInfo();
		}

		if (!$this->AccessCode) {
			$this->AccessCode = MarketoUtilities::GenerateStrongPassword(9,1,'ud');
		}

		return parent::onBeforeWrite();
	}

	public function getMenuTitle() {
		return "$this->Email ($this->AccessCode on $this->ClientInfo)";
	}

	public function updateCMSFields(FieldList $fields) {

    	$fields->addFieldsToTab('Main',
    		NumericField::create('ID','Authorization ID')->setDisabled(true),
    		ReadonlyField::create('AccessLink','Access Link',$this->AbsoluteLink()),
    		EmailField::create('Email'),
    		TextField::create('ClientKey', 'Client Key'),
    		TextField::create('ClientInfo', 'Client Info'),
    		TextField::create('AccessCode'),
    		DatetimeField::create('EmailSent')
    	);

	}

	public function EmailAuthorization() {
		if (!$this->Page()) return false;
		if (!$this->Email) return false;
		if (!$this->AccessCode) return false;

		$Link = $this->AbsoluteLink();

		$body = <<<HTML
<h1>Here's your access link!</h1>
<p>The link below was specially baked just for you.</p>

<h3>Valid only on the following device:</h3>
<p>$this->ClientInfo</p>

<h3>Access link:</h3>
<p>$Link</p>

<p><strong>IMPORTANT:</strong> This access link will ONLY work on the device you originally requested it from.</p>

<p>Thank you,<br/>
Marketing Developers</p>
HTML;
		$email = new Email(MAIL_SENDER_ADDRESS, $this->Email, 'Your Access Code for '.$this->Page()->Title, $body);
		$email->replyTo(MAIL_REPLY_TO_ADDRESS);
		$email->send();

		$this->EmailSent = (string)SS_Datetime::now();
		return true;
	}



	/**
	 * Helpers...
	 */

	const EmailEmpty		= 1;
	const EmailMissing		= 2;
	const EmailNotAllowed	= 4;
	const PageInvalid		= 8;
	const AccessCodeMissing	= 16;
	const PageHasNoEmail	= 32;
	const DeviceWrong		= 64;

	/**
	 * @param AuthorizedPage $Page
	 * @param string $Email
	 * @param string $AccessCode
	 * @param string $ClientKey
	 * @param string $ClientInfo
	 * @return int
	 */
	static public function AuthorizationErrors(AuthorizedPage $Page,$Email,$AccessCode,$ClientKey=null,$ClientInfo=null) {
		$ErrorCode	= 0;
		$ClientKey	= $ClientKey ? $ClientKey : Authorization::generateClientKey();
		$ClientInfo	= $ClientInfo ? $ClientInfo : Authorization::generateClientInfo();
		$Email		= strtolower($Email);
		$AccessCode	= strtoupper($AccessCode);

		$Auths = Authorization::get()->filterAny(array(
			'PageID'		=> $Page->ID,
			'Email'			=> $Email,
			'AccessCode'	=> $AccessCode,
			'ClientKey'		=> $ClientKey,
			'ClientInfo'	=> $ClientInfo,
		));

		if (!$Email) {
			$ErrorCode |= static::EmailEmpty;
		} else if (!$Auths->filter('Email',$Email)->count()) {
			$ErrorCode |= static::EmailMissing;
		}

		if (!$Page->ID) {
			$ErrorCode |= static::PageInvalid;
		} else {
			if (
				!($ErrorCode & static::EmailEmpty) &&
				!$Page->IsAllowedEmail($Email)
			) {
				$ErrorCode |= static::EmailNotAllowed;
			}
		}

		if (!$AccessCode) {
			$ErrorCode |= static::AccessCodeMissing;
		}

		/**
		 * At this point, if there's an error, it makes no sense
		 * to do any further validation since either the Email
		 * has never been submitted for this page, or the page
		 * has no authorizations yet (or both).
		 */
		if ($ErrorCode) {
			return $ErrorCode;
		}

		if (!$Auths->filter(array('PageID'=>$Page->ID,'Email'=>$Email))->count()) {
			$ErrorCode |= static::PageHasNoEmail;
		} else if (!$Auths->filter(array('PageID'=>$Page->ID,'Email'=>$Email,'AccessCode'=>$AccessCode,'ClientKey' => $ClientKey,'ClientInfo' => $ClientInfo))->count()) {
			$ErrorCode |= static::DeviceWrong;
		}

		return $ErrorCode;
	}

	/**
	 * @param AuthorizedPage $Page
	 * @param string $Email
	 * @param string $AccessCode
	 * @param string $ClientKey
	 * @param string $ClientInfo
	 * @return Authorization|boolean
	 */
	static public function Fetch(AuthorizedPage $Page,$Email,$AccessCode,$ClientKey=null,$ClientInfo=null) {
		if (!$Page || !$Page->ID) return false;
		$ClientKey	= $ClientKey ? $ClientKey : Authorization::generateClientKey();
		$ClientInfo	= $ClientInfo ? $ClientInfo : Authorization::generateClientInfo();
		$Email		= strtolower($Email);
		$AccessCode	= strtoupper($AccessCode);

		if (!$Page->IsAllowedEmail($Email)) return false;

		return Authorization::get()->filter(
			array(
				'PageID'		=> $Page->ID,
				'Email'			=> $Email,
				'AccessCode'	=> $AccessCode,
				'ClientKey'		=> $ClientKey,
				'ClientInfo'	=> $ClientInfo,
			)
		)->First();
	}

	/**
	 * Generates a sha1 hash of client-specific variables allowing us to isolate an authorization code to a specific device.
	 *
	 * If you choose not to use cookies:
	 * It is NOT 100% accurate, but it's accurate enough. The goal is to narrow the window.
	 * Why not use IP address?  IP addresses on mobile networks change with every request.
	 *
	 * Using cookies:
	 * A cookie will be generated by hashing the *current* IP address with microtime.
	 * IP address works in this case because it's only used WHEN SETTING the cookie.
	 * It's not used for validation, it's used only to help ensure uniqueness.
	 *
	 * @param bool $use_cookie Default is true
	 * @return mixed|string
	 */
	static public function generateClientKey($use_cookie=true) {
		if ($use_cookie) {
			if (!($client = Cookie::get('a_client'))) {
				// Note: _mkto_trk is not always available, but that's okay! It will return null when it's not.
				// It's not vital, but when it exists, it adds an additional level of uniqueness to the hash.
				$client = sha1(microtime() . '|' . $_SERVER['REMOTE_ADDR'] . '|' . Cookie::get('_mkto_trk'));
			}
			// Set cookie every time (even when it's already set).
			// This allows them 14 days of pure inactivity before the token resets.
			Cookie::set('a_client',$client,14,'/','.marketo.com');
			return $client;
		}
		return sha1(
			$_SERVER['HTTP_ACCEPT'] . '|' .
			$_SERVER['HTTP_USER_AGENT'] . '|' .
			$_SERVER['HTTP_ACCEPT_ENCODING'] . '|' .
			$_SERVER['HTTP_ACCEPT_LANGUAGE']
		);
	}

	static public function generateClientInfo() {
		if (isset($_SERVER['HTTP_USER_AGENT'])) {
			return $_SERVER['HTTP_USER_AGENT'];
		} else {
			return 'Empty User-agent';
		}
	}

}