<?php
/**
 * User: nathanbrauer
 * Date: 4/4/14 1:36 PM
 */
class AuthorizedPage extends Page {

	public $FacebookSupported = false;
//	public $LayoutToUse = 'Open';

//	private static $icon = '_static/images/silverstripe/icons/AuthorizedPage.png';
//	private static $default_child = '';
//	private static $allowed_children = array(
//	);

	private static $db = array(
		'AllowedEmailAddresses' => 'Text',
		'RedirectURL' => 'Varchar(255)',
	);

	private static $has_one = array(
	);

	private static $belongs_to = array(
	);
	
	private static $has_many = array(
		'Authorizations' => 'Authorization'
	);

	private static $many_many = array(
	);

	private static $belongs_many_many = array(
	);

	private static $many_many_extraFields = array(
	);

	public function setAllowedEmailAddresses($value) {
		$this->setField('AllowedEmailAddresses',strtolower(trim($value)));
	}


	public function getCMSFields() {
		$fields = parent::getCMSFields();

		$fields->addFieldToTab('Root.Email Addresses',TextareaField::create('AllowedEmailAddresses')->setDescription('One email address per line.')->setRows(50));
		$fields->addFieldToTab('Root.Main',TextField::create('RedirectURL')->setDescription('Instead of including content on the page, redirect to an external URL upon authentication.'),'Content');

		return $fields;
	}

	public function IsAllowedEmail($Email) {
		$Emails = preg_split('/\s*[\r\n]+\s*/i',$this->AllowedEmailAddresses);
		return in_array(strtolower($Email),$Emails);
	}


	public function getJSONOutput() {
		$AllData = $this->getAllData();
		unset($AllData['AllowedEmailAddresses']);
		unset($AllData['Content']);
		unset($AllData['RedirectURL']);
		return $AllData;
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

	function init() {
		return parent::init();
	}

	function index() {
		if (!$this->Authorization($_GET)) {
			$Errors = $this->AuthorizationErrors($_GET);
			$ShowErrorCode = '<small style="color:#999;font-weight:bold;">Error '.$Errors.':</small>';

			if ($Errors & Authorization::EmailEmpty) {
				// Most likely the user is a new visitor to the page
			} else if (isset($_GET['EmailSent'])) {
				if ($Errors & Authorization::EmailNotAllowed) {
					$this->ErrorMessages[] = '<p style="color:red;font-weight:bold;">This email address is not allowed access to this page.</p>';
				} else {
					$this->ErrorMessages[] = '<p style="color:blue;font-weight:bold;">Please check your email for your access link.</p>';
				}
			} else {
				if ($Errors & Authorization::PageInvalid) {
					$this->ErrorMessages[] = $ShowErrorCode;
					$this->ErrorMessages[] = '<p style="color:red;font-weight:bold;">Internal Error: The Page doesn\'t exist.</p>';
				} else if ($Errors & Authorization::EmailNotAllowed) {
					$this->ErrorMessages[] = '<p style="color:red;font-weight:bold;">This email address is not allowed access to this page.</p>';
				} else if ($Errors & Authorization::PageHasNoEmail) {
					$this->ErrorMessages[] = '<p>Welcome back!</p>';
				} else if ($Errors & Authorization::DeviceWrong) {
					$this->ErrorMessages[] = $ShowErrorCode;
					$this->ErrorMessages[] = '<p style="color:red;font-weight:bold;">Looks like you\'ve registered this email address using a different device or browser.</p>';
					$this->ErrorMessages[] = '<p style="color:red;font-weight:bold;">You\'ll need to request a new access link for each device.</p>';
				} else if (!($Errors & Authorization::AccessCodeMissing)) {
					$this->ErrorMessages[] = $ShowErrorCode;
					$this->ErrorMessages[] = '<p style="color:red;font-weight:bold;">This link has expired. Please generate a new link below.</p>';
				}
			}

			//$this->ErrorMessages[] = '<p>Please enter your email address. An access code will be emailed to you to verify your identity.</p>';

			// this is an example of what we could do to facilitate translation - this causes more queries though...
			$this->ErrorMessages[] = $this->TranslateString('<p>Please enter your email address. An access code will be emailed to you to verify your identity.</p>','AuthorizedPage');


			return $this->renderWith(array('Security','Page'));
		}

		if ($this->data()->RedirectURL) {
			return '<script>window.location="'.Convert::raw2js($this->data()->RedirectURL).'"</script>';
			// This method does not pass on the referral URL when clicking from an email
			return $this->redirect($this->data()->RedirectURL);
		}

		return $this->renderWith(array($this->data()->ClassName,'Page'));
	}

	function new_authorization() {
		
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

	function getLayoutToUse() {
		if (!$this->Authorization($_GET)) {
			return 'Enclosed';
		}
		return $this->data()->LayoutToUse;
	}
}