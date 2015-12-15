<?php
/**
 * User: nathanbrauer
 * Date: 4/4/14 1:36 PM
 */
class AuthorizedPage extends Page {

	private static $db = array(
		'AllowedEmailAddresses' => 'Text',
		'RedirectURL' => 'Varchar(255)',
	);

	private static $has_many = array(
		'Authorizations' => 'Authorization'
	);

	public function setAllowedEmailAddresses($value) {
		$this->setField('AllowedEmailAddresses',strtolower(trim($value)));
	}


	public function getCMSFields() {
		$fields = parent::getCMSFields();

		$fields->addFieldToTab('Root.Email Addresses',
			TextareaField::create('AllowedEmailAddresses')
				->setDescription('One email address per line.')
				->setRows(50)
		);

		$fields->addFieldToTab('Root.Main',
			TextField::create('RedirectURL')
				->setDescription('Instead of including content on the page, redirect to an external URL upon authentication.')
		,'Content');

		return $fields;
	}

	public function IsAllowedEmail($Email) {
		$Emails = preg_split('/\s*[\r\n]+\s*/i',$this->AllowedEmailAddresses);

		return in_array(strtolower($Email),$Emails);
	}

}

class AuthorizedPage_Controller extends Page_Controller {

	private $Authorization			= null;
	private $AuthorizationErrors	= null;
	private $ErrorMessages			= array();

	private static $allowed_actions = array(
		'index',
		'getForm',
		'new_authorization',
		'validate' => 'validateOneTimeCode',
		'validateOneTimeCode'
	);

	//@TODO template and translation file
	function index() {

		if (!$this->Authorization($this->request->getVar('Email'),$this->request->getVar('AccessCode'))) {
			$Errors = $this->AuthorizationErrors($this->request->getVar('Email'),$this->request->getVar('AccessCode'));
			$ShowErrorCode = '<small style="color:#999;font-weight:bold;">Error '.$Errors.':</small>';

			if ($Errors & Authorization::EMAIL_EMPTY) {
				// Most likely the user is a new visitor to the page
			} else if ($this->request->getVar('EmailSent')) {
				if ($Errors & Authorization::EMAIL_NOT_ALLOWED) {
					$this->ErrorMessages[] = '<p style="color:red;font-weight:bold;">This email address is not allowed access to this page.</p>';
				} else {
					$this->ErrorMessages[] = '<p style="color:blue;font-weight:bold;">Please check your email for your access link.</p>';
				}
			} else {
				if ($Errors & Authorization::PAGE_INVALID) {
					$this->ErrorMessages[] = $ShowErrorCode;
					$this->ErrorMessages[] = '<p style="color:red;font-weight:bold;">Internal Error: The Page doesn\'t exist.</p>';
				} else if ($Errors & Authorization::EMAIL_NOT_ALLOWED) {
					$this->ErrorMessages[] = '<p style="color:red;font-weight:bold;">This email address is not allowed access to this page.</p>';
				} else if ($Errors & Authorization::PAGE_HAS_NO_EMAIL) {
					$this->ErrorMessages[] = '<p>Welcome back!</p>';
				} else if ($Errors & Authorization::DEVICE_WRONG) {
					$this->ErrorMessages[] = $ShowErrorCode;
					$this->ErrorMessages[] = '<p style="color:red;font-weight:bold;">Looks like you\'ve registered this email address using a different device or browser.</p>';
					$this->ErrorMessages[] = '<p style="color:red;font-weight:bold;">You\'ll need to request a new access link for each device.</p>';
				} else if (!($Errors & Authorization::ACCESS_CODE_MISSING)) {
					$this->ErrorMessages[] = $ShowErrorCode;
					$this->ErrorMessages[] = '<p style="color:red;font-weight:bold;">This link has expired. Please generate a new link below.</p>';
				}
			}

			$this->ErrorMessages[] = '<p>Please enter your email address. An access code will be emailed to you to verify your identity.</p>';

			return $this->renderWith(array('Security','Page'));
		}

		if ($this->data()->RedirectURL) {

			$this->Authorization->generateOneTime();

			$this->Authorization->write();

			$redirect = self::join_links($this->data()->RedirectURL, '?ott=' . $this->Authorization->OneTimeCode);

			return '<script>window.location="' . Convert::raw2js($redirect) . '"</script>';
		}

		return $this->renderWith(array($this->data()->ClassName,'Page'));
	}

	public function new_authorization() {
		if (empty($this->request->postVars()) || !$this->data()) return $this->redirectBack();

		// We will create an authorization EVEN IF the email is not allowed.
		// This allows us to see who requested access, even if they're not allowed.
		// But, we email email them the access code.

		$email = strtolower($this->request->postVar('Email'));

		$Auth = Authorization::get()->filter(array(
			'PageID'		=> $this->ID,
			'Email'			=> $email,
			'ClientKey'		=> Authorization::generateClientKey(),
			'ClientInfo'	=> Authorization::generateClientInfo(),
		))->First();

		if (!$Auth) {
			$Auth = new Authorization();
			$Auth->PageID	= $this->ID;
			$Auth->Email	= $email;
			$Auth->write();
		}

		if ($this->data()->IsAllowedEmail($email)) {
			$Auth->EmailAuthorization();
		}

		$Auth->write(); // Write for both so it updates EmailSent time

		return $this->redirect($this->data()->AbsoluteLink().'?Email='.rawurlencode($email).'&EmailSent');
	}

	/**
	 * Validates the OneTimeCode against Authorization.
	 * Valid requests need tobe sent as POST with ott=OneTimeCode
	 * @return JSON
	 */
	public function validateOneTimeCode() {
		
		$return = array('valid' => false);
		
		if($this->request->postVar('ott')) {
			if ($ottcheck = Authorization::get()->filter('OneTimeCode', $this->request->postVar('ott'))->last()) {
				$return['valid'] = true;
				//As this token as been found we'll remove it and write the Authorization.
				//@TODO potentially add a log of this occur so use cna be tracked?
				$ottcheck->OneTimeCode = null;
				$ottcheck->write();
			}
		}
		
		return $this->renderWith('json', array('json' => json_encode($return)));
	}
	
	/**
	 * @return bool|Authorization
	 */
	public function Authorization($email, $accessCode) {
		if (!is_null($this->Authorization)) return $this->Authorization;
		return $this->Authorization = Authorization::Fetch($this->data(), $email, $accessCode);
	}

	/**
	 * @return int
	 */
	public function AuthorizationErrors($email, $accessCode) {
		if (!is_null($this->AuthorizationErrors)) return $this->AuthorizationErrors;
		return $this->AuthorizationErrors = Authorization::AuthorizationErrors($this->data(), $email, $accessCode);
	}

	public function getContent() {
		if ($this->ErrorMessages) {
			return implode('',$this->ErrorMessages);
		} else {
			return $this->data()->Content;
		}
	}

	public function getForm() {

		if (!$this->data()) return false;

		if (!$this->Authorization($this->request->getVar('Email'),$this->request->getVar('AccessCode'))) {
			$fields = new FieldList();
			$fields->add(
				EmailField::create(
					'Email',
					'Email Address',
					strtolower($this->request->param('Email'))
				)
			);

			$actions = new FieldList();
			if ($this->request->param('Email')) {
				$actions->add(FormAction::create('new_authorization','Re-Email Access Link'));
			} else {
				$actions->add(FormAction::create('new_authorization','Email Access Link'));
			}

			return new Form($this,'getForm',$fields,$actions);
		}
	}

	//@TODO what's this do?
	public function getLayoutToUse() {

		if (!$this->Authorization($this->request->getVar('Email'),$this->request->getVar('AccessCode'))) {
			return 'Enclosed';
		}
		return $this->data()->LayoutToUse;
	}
}