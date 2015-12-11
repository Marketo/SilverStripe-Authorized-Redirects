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
		'new_authorization'
	);

	//@TODO template and translation file
	function index() {
		//@TODO Remove $_GET calls
		if (!$this->Authorization($_GET)) {
			$Errors = $this->AuthorizationErrors($_GET);
			$ShowErrorCode = '<small style="color:#999;font-weight:bold;">Error '.$Errors.':</small>';

			if ($Errors & Authorization::EMAIL_EMPTY) {
				// Most likely the user is a new visitor to the page
			} else if (isset($_GET['EmailSent'])) {
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
			// This method does not pass on the referral URL when clicking from an email
			//return $this->redirect($this->data()->RedirectURL);
		}

		return $this->renderWith(array($this->data()->ClassName,'Page'));
	}

	function new_authorization() {
		//@TODO remove use of $_POST
		if (!isset($_POST) || empty($_POST)) return $this->redirectBack();
		
		$Page = $this->data();
		if (!$Page) return $this->redirectBack();

		// We will create an authorization EVEN IF the email is not allowed.
		// This allows us to see who requested access, even if they're not allowed.
		// But, we email email them the access code.

		$Auth = Authorization::get()->filter(array(
			'PageID'		=> $Page->ID,
			'Email'			=> $_POST['Email'],
			'ClientKey'		=> Authorization::generateClientKey(),
			'ClientInfo'	=> Authorization::generateClientInfo(),
		))->First();

		if (!$Auth) {
			$Auth = new Authorization();
			$Auth->PageID	= $this->data()->ID;
			$Auth->Email	= strtolower($_POST['Email']);
			$Auth->write();
		}

		if ($Page->IsAllowedEmail($_POST['Email'])) {
			$Auth->EmailAuthorization();
		}

		$Auth->write(); // Write for both so it updates EmailSent time

		return $this->redirect($this->data()->AbsoluteLink().'?Email='.rawurlencode($_POST['Email']).'&EmailSent');
	}

	/**
	 * @return bool|Authorization
	 */
	function Authorization($Data) {
		if (!is_null($this->Authorization)) return $this->Authorization;
		return $this->Authorization = Authorization::Fetch($this->data(),@$Data['Email'],@$Data['AccessCode']);
	}

	/**
	 * @return int
	 */
	function AuthorizationErrors($Data) {
		if (!is_null($this->AuthorizationErrors)) return $this->AuthorizationErrors;
		//@TODO fix @ calls
		return $this->AuthorizationErrors = Authorization::AuthorizationErrors($this->data(),@$Data['Email'],@$Data['AccessCode']);
	}

	function getContent() {
		if ($this->ErrorMessages) {
			return implode('',$this->ErrorMessages);
		} else {
			return $this->data()->Content;
		}
	}

	function getForm() {
		//@TODO fix submit flow here
		if (!($Page = $this->data())) return false;
		if (!$this->Authorization($_GET)) {
			$fields = new FieldList();
			$fields->add(EmailField::create('Email','Email Address',isset($_REQUEST['Email']) ? strtolower($_REQUEST['Email']) : ''));

			$actions = new FieldList();
			if (isset($_GET['EmailSent'])) {
				$actions->add(FormAction::create('Submit','Re-Email Access Link'));
			} else {
				$actions->add(FormAction::create('Submit','Email Access Link'));
			}

			return new Form($this,'new_authorization/',$fields,$actions);
		}
	}

	//@TODO what's this do?
	function getLayoutToUse() {
		//@TODO fix $_GET
		if (!$this->Authorization($_GET)) {
			return 'Enclosed';
		}
		return $this->data()->LayoutToUse;
	}
}