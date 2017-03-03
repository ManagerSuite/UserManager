<?php
/*
Copyright (c) 2016-2017 ManagerSuite(https://github.com/ManagerSuite)

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/


class UserManager extends Standard implements iUserSystem {
	public $config;
	private $groupCache;
	public $userCache;
	
	public $userStructure;
	
	const User = "User";
	
	static public $User = "User";
	
	public $loggedIn;
	
	
	
	public $Login = "UserManager_Widgets_Login";
	public $Logout = "UserManager_Widgets_Logout";
	public $Register = "UserManager_Widgets_Register";
	public $Group = "UserManager_Widgets_Groups";
	public $UserBlock = "UserManager_Widgets_UserBlock";
	public $Perms = "UserManager_Widgets_Perms";
	public $ChangePassword = "UserManager_Widgets_ChangePassword";
	public $ChangeEmail = "UserManager_Widgets_ChangeEmail";
	public $ResetPassword = "UserManager_Widgets_ResetPassword";
	public $ChangePicture = "UserManager_Widgets_ChangePicture";
	
	
	public $Widgets = [
		"Login" => "UserManager_Widgets_Login",
		"Logout" => "UserManager_Widgets_Logout",
		"Register" => "UserManager_Widgets_Register",
		"Group" => "UserManager_Widgets_Groups",
		"UserBlock" => "UserManager_Widgets_UserBlock",
		"Perms" => "UserManager_Widgets_Perms",
		"ChangePassword" => "UserManager_Widgets_ChangePassword",
		"ChangeEmail" => "UserManager_Widgets_ChangeEmail",
		"ResetPassword" => "UserManager_Widgets_ResetPassword",
		"ChangePicture" => "UserManager_Widgets_ChangePicture"
	];
	
	public function init() {
		$this->userCache = [];
		$this->groupCache = [];
		$this->userStructure = new Structure(function ($data) {
			$img = "";
			$path = Standards::standard("UserSystem")->config["profilePictureStorageDirectory"]."u".$data["id"].".png";
			if (file_exists(Document_root.$path)) {
				$img = "<img style='max-width: 40px; max-height: 40px; vertical-align: middle; border-radius: 1000em;' src='".Format_Link($path)."'/>";
			}else{
				$img = Theme::icon("person_outline", "UserSystem.none")->get();
			}
			return "<div class='UserSystem_User_Block'>".$img." <span style='margin: 0 .5em;'></span> <a class='UserSystem_Account' href='".Linker::get("Account", ["id" => $data["id"]])."'>".$data["username"]."</a></div>";
		});
	}
	
	public function checkLoggedIn() {
		if (!isset($_SESSION["UserManager_user_login"])) {
			return false;
		}else{
			return $this->getUserFromId($_SESSION["UserManager_user_login"]["userid"]);
		}
	}
	
	public function isLoggedIn() {
		if ($this->loggedIn === false) return false;
		return true;
	}
	
	public function getLoggedIn() {
		return $this->loggedIn;
	}
	
	private function sendConfirmEmail($username, $emailAddress, $id) {
		$sub = new Structure($this->config["Sign_Up_Email_Subject"]);
		$body = new Structure($this->config["Sign_Up_Email_Body"]);
		$from = $this->config["Sign_Up_Email_Sender"];
		
		//Setup the confirm url
		$url = createProcessLink("u_s_cfirm", ["i" => md5($id), "a" => $id, "b" => md5($username)]);
		
		$vars = [
			"username" => $username,
			"email" => $emailAddress,
			"confirm_url" => $url
		];
		
		$email = new Email($from,
		$sub->get($vars),
		$body->get($vars));
		
		$email->addHeader("Content-Type", "text/html; charset=ISO-8859-1");
		
		$email->send([$emailAddress]);
	}
	
	
	//User register
	
	public function registerUser($username, $email, $password, $needsConfirm = true) {
		//Check if username or email is taken.
		$finder = new Data_Finder();
		$finder->where("", "username", "=", $username);
		$finder->where("OR", "email", "=", $email);
		$selected = Data_Select(GetTable("UserManager.users"), $finder);
		if (count($selected) > 0) {
			foreach ($selected as $user) {
				if (strtolower($user["username"]) == strtolower($username) AND strtolower($user["email"]) == strtolower($email) AND $user["confirmed"] == 0) return STANDARD_USER_SYSTEM_ACCOUNT_NOT_CONFIRMED;
				
				if (strtolower($user["username"]) == strtolower($username)) return STANDARD_USER_SYSTEM_USERNAME_TAKEN;
				if (strtolower($user["email"]) == strtolower($email)) return STANDARD_USER_SYSTEM_EMAIL_TAKEN;
			}
		}
		
		//Start building the user.
		$builder = new Data_Builder();
		$builder->add("username", $username);
		$builder->add("email", $email);
		
		//Get the password hash
		$hash = password_hash($password, PASSWORD_DEFAULT);
		$builder->add("password", $hash);
		
		//If the user needs to confirm their email, send an email and lock the account.
		if ($needsConfirm) {
			$builder->add("confirmed", 0);
		}else{
			$builder->add("confirmed", 1);
		}
		
		//Set the status to approved user.
		$builder->add("status", 2);
		
		//Create the user.
		$newUserId = Data_Insert(GetTable("UserManager.users"), $builder);
		
		if ($newUserId === false)
			return false;
		
		//Success
		
		if ($needsConfirm)
			$this->sendConfirmEmail($username, $email, $newUserId);
		
		return true;
	}
	
	private function findUser($values, $type) {
		if (isset($this->userCache[$values]))
		return $this->userCache[$values][0];
		
		$find = "";
		if ($type == 1) {
			$find = ["#" => $values];
		}else if($type == 2){
			$find = ["=" => ["username", $values]];
		}
		
		$users = Standards::findEntities("UserSystem.User", $find);
		
		if ($users === false)
			return false;
		
		if (count($users) == 1) {
			$this->userCache[$values] = [$users[0], []];
			return $users[0];
		}
		
		return false;
	}
	
	public function getUserFromId($id) {
		return $this->findUser($id, 1);
	}
	
	public function getUserFromName($id) {
		return $this->findUser($id, 2);
	}
	
	
	//Login
	public function checkPassword($handle, $password) {
		$match = false;
		
		$finder = new Data_Finder();
		if (filter_var($handle, FILTER_VALIDATE_EMAIL) !== false) {
			$finder->where("", "email", "=", $handle);
		}else{
			$finder->where("", "username", "=", $handle);
		}
		
		$finder->where("AND", "confirmed", "=", 1);
		
		$user = Data_Select(GetTable("UserManager.users"), $finder);
		if (count($user) == 0)
			return false;
		
		if (password_verify($password, $user[0]['password']))
			return $user[0];
		
		return false;
	}
	
	public function login($handle, $password) {
		$user = $this->checkPassword($handle, $password);
		if ($user !== false) {
			//Regen the id for safe stuff.
			session_regenerate_id();
			
			$_SESSION["UserManager_user_login"] = [
				"userid" => $user["id"],
				"time" => date("Y-m-d H:i:s")
			];
			
			return true;
		}else{
			return false;
		}
	}
	
	public function logout() {
		if (Standards::UserSystem()->event("user.logout")->invoke([
			"user" => Standards::UserSystem()->getLoggedIn()
		])) return false;
		
		unset($_SESSION["UserManager_user_login"]);
		session_regenerate_id();
		return true;
	}
	
	
	//Groups
	public function getGroup($name) {
		if (isset($this->groupCache[$name]))
			return json_decode($this->groupCache[$name]["permission"]);
		
		$groups = Data_Select(GetTable("UserManager.groups"), Quick_Find([["name", "=", $name]]));
		if (count($groups) > 0) {
			$this->groupCache[$name] = $groups[0];
			return json_decode($groups[0]["permission"]);
		}
		
		return false;
	}
	
	public function setGroup($name, $arr) {
		$groups = Data_Select(GetTable("UserManager.groups"), Quick_Find([["name", "=", $name]]));
		if (count($groups) == 1) {
			$builder = new Data_Builder();
			$builder->add("permission", json_encode($arr));
			Data_Update(GetTable("UserManager.groups"), $builder, Quick_Find([["id", "=", $groups["id"]]]));
			return true;
		}
		return false;
	}
	
	public function createGroup($name, $arr) {
		$groups = Data_Select(GetTable("UserManager.groups"), Quick_Find([["name", "=", $name]]));
		if (count($groups) == 0) {
			$builder = new Data_Builder();
			$builder->add("permission", json_encode($arr));
			$builder->add("name", $name);
			Data_Insert(GetTable("UserManager.groups"), $builder);
			return true;
		}
		return false;
	}
	
	public function removeGroup($name) {
		if ($this->getGroup($name) === false)
			return false;
		
		$builder = new Data_Builder();
		$builder->add("status", 1);
		$builder->add("removeTime", date("Y-m-d H:i:s"));
		
		$groupUsers = Data_Update(GetTable("UserManager.perms"), $builder, Quick_Find([["group", "=", $name], ["status", "=", 2]]));
		
		Data_Delete(GetTable("UserManager.groups"), Quick_Find([["name", "=", $name]]));
		
		return true;
	}
	
	
}

onProcess("us_s_usr", function ($vars) {
	$s = $vars["search"];
	if (strlen($s) <= 1 OR strlen($s) > 255) {
		die("[]");
	}
	$finder = Quick_Find([["username", "LIKE", "%".$s."%"]]);
	$finder->addQuery("LIMIT 10");
	$finder->columns = "`username`";
	$found = Data_Select(GetTable("UserManager.users"), $finder);
	$rtn = [];
	foreach ($found as $f) {
		$rtn[$f["username"]] = $f["username"];
	}
	die(json_encode($rtn));
});

class UserManager_Widgets_ChangeEmail extends Widget {
	public $userId = -1;
	
	function __construct($userId) {
		$this->userId = $userId;
	}
	
	function get() {
		$form = new Form("UserManager_change_em");
		
		$email = new Text();
		$email->character_min = 5;
		$email->character_max = 256;
		$email->placeholder = "Email";
		
		$form->addInput("email", $email);
		
		$pw = new Text("password");
		$pw->character_min = Standards::standard("UserSystem")->config["minPasswordLength"];
		$pw->character_max = Standards::standard("UserSystem")->config["maxPasswordLength"];
		$pw->placeholder = "Password";
		
		$form->addInput("password", $pw);
		
		$form->structure = new Structure(Theme::grid([
			["%email%", "%password%"]
		], "UserSystem.login")->get().Theme::input_submit("Change Email", "UserSystem.passwordChange")->get());
		
		$form->on("success", function ($data) {
			$user = Standards::findEntities("UserSystem.User", ["#" => $this->userId])[0];
			
			if (!$user->checkPassword($data["password"]))
				return Message::QuickError("Wrong password.");
			
			if (filter_var($data["email"], FILTER_VALIDATE_EMAIL) === false)
				return Message::QuickError("Invalid email.");
			
			$rtn = $user->changeEmail($data["email"]);
			if ($rtn === false)
				return Message::QuickError("That email is already in use.");
			
			$msg = new Message();
			$msg->add("form", Message::Success("Follow the link confirmation sent to ".$data["email"]." in order to set the account email.", 100));
			
			return $msg;
		});
		
		$form->check();
		
		return $form->get();
	}
}

class UserManager_Widgets_ChangePassword extends Widget {
	public $userId = -1;
	
	function __construct($userId) {
		$this->userId = $userId;
	}
	
	function get() {
		$form = new Form("UserManager_change_pw");
		
		$password = new Text("password");
		
		$password->character_max = Standards::standard("UserSystem")->config["maxPasswordLength"];
		$password->character_min = Standards::standard("UserSystem")->config["minPasswordLength"];
		$password->placeholder = "New password";
		
		$confirmPassword = new Text("password");
		
		$confirmPassword->placeholder = "Retype password";
		$confirmPassword->character_max = Standards::standard("UserSystem")->config["maxPasswordLength"];
		$confirmPassword->character_min = Standards::standard("UserSystem")->config["minPasswordLength"];
		
		$oldPassword = new Text("password");
		
		$oldPassword->placeholder = "Current password";
		
		$oldPassword->character_max = Standards::standard("UserSystem")->config["maxPasswordLength"];
		$oldPassword->character_min = Standards::standard("UserSystem")->config["minPasswordLength"];
		
		$form->addInput("newPassword", $password);
		$form->addInput("confirmPassword", $confirmPassword);
		$form->addInput("oldPassword", $oldPassword);
		
		$form->structure = new Structure(Theme::grid([
			["%newPassword%", "%confirmPassword%"],
			["%oldPassword%"]
		], "UserSystem.login")->get().Theme::input_submit("Save password", "UserSystem.passwordChange")->get());
		
		$form->on("success", function ($data) {
			if ($data["newPassword"] != $data["confirmPassword"])
				return Message::QuickError("Passwords do not match.");
			
			$user = Standards::findEntities("UserSystem.User", ["#" => $this->userId])[0];
			
			if (!$user->checkPassword($data["oldPassword"]))
				return Message::QuickError("Current password does not match.");
			
			
			$user->setPassword($data["newPassword"]);
			
			$user->save();
			
			$msg = Message::QuickSuccess("Password changed.");
			
			return $msg;
		});
		
		$form->check();
		
		return $form->get();
	}
}


class UserManager_Widgets_ChangePicture extends Widget {
	public $userId = -1;
	
	function __construct($userId) {
		$this->userId = $userId;
	}
	
	function get() {
		$form = new Form("UserManager_change_pp");
		
		$image = new Image();
		$image->max_size = intval(Standards::standard("UserSystem")->config["profilePictureMaxSize"]);
		$form->addInput("pic", $image);
		
		$form->structure = new Structure(Theme::grid([
			["%pic%"]
		], "UserSystem.profilePicture")->get().Theme::input_submit("Save profile picture", "UserSystem.profilePicture")->get());
		
		$form->on("success", function ($data) {
			if (count($data["pic"]) == 0)
				return Message::QuickError("No image selected.");
			
			$image = imagecreatefromstring(base64_decode($data["pic"][0]));
			imagesavealpha($image, true);
			imagepng($image, Document_root.Standards::standard("UserSystem")->config["profilePictureStorageDirectory"]."u".$this->userId.".png");
			
			imagedestroy($image);
			
			$msg = Message::QuickSuccess("Profile picture changed.");
			return $msg;
		});
		
		$form->check();
		
		return $form->get();
	}
}

class UserManager_Widgets_ResetPassword extends Widget {
	static public $index = 0;
	
	public function __construct() {
		self::$index++;
	}
	
	function get() {
		$form = new Form("UserManager_reset_pw".self::$index);
		
		$password = new Text("password");
		
		$password->character_max = Standards::standard("UserSystem")->config["maxPasswordLength"];
		$password->character_min = Standards::standard("UserSystem")->config["minPasswordLength"];
		$password->placeholder = "Last password you remember";
		
		$email = new Text();
		
		$email->placeholder = "Email";
		
		$form->addInput("email", $email);
		$form->addInput("lastPassword", $password);
		
		$form->structure = new Structure(Theme::grid([
			["%email%", "%lastPassword%"]
		], "UserSystem.login")->get().Theme::input_submit("Send reset email", "UserSystem.passwordReset")->get());
		
		$form->on("success", function ($data) {
			$m = new Message();
			if (filter_var($data["email"], FILTER_VALIDATE_EMAIL) === false) {
				$m->add("form", Message::QuickError("Invalid email"));
				return $m;
			}
			
			$users = Standards::findEntities("UserSystem.User", ["=" => ["email", $data["email"]]]);
			
			if (count($users) != 1) {
				return Message::QuickSuccess("If your account was found, an email containg a password reset will be sent to ".$data["email"]."."); //Not found.
			}
			
			$hash = md5(rand(100, 999999997));
			$hash2 = md5(rand(100, 999999997));
			
			Data_Delete(GetTable("UserManager.reset"), Quick_Find([["user", "=", $users[0]->getId()]]));
			
			$builder = new Data_Builder();
			$builder->add("type", STANDARD_USER_SYSTEM_PASSWORD_RESET);
			$builder->add("newvalue", $hash2);
			$builder->add("oldvalue", $hash);
			$builder->add("user", $users[0]->getId());
			
			$rwid = Data_Insert(GetTable("UserManager.reset"), $builder);
			
			$msg = "Hello ".$users[0]->getUsername().", to reset your password please navigate to the following url in a browser ".createProcessLink("u_s_rste", ["a" => $hash, "b" => $hash2, "i" => $users[0]->getId(), "o" => md5($rwid)]);
			
			$mail = new Email(true, "Account password reset", $msg);
			$mail->send([$users[0]->getEmail()]);
			
			return Message::QuickSuccess("If your account was found, an email containg a password reset will be sent to ".$data["email"]."."); //Found.
		});
		
		$form->check();
		
		return $form->get();
	}
}

onProcess("u_s_rste", function ($d) {
	$errorMsg = "An error has occurred.";
	
	if (!isset($d["a"])) {
		echo $errorMsg;
		return false;
	}
	
	if (!isset($d["b"])) {
		echo $errorMsg;
		return false;
	}
	
	if (!isset($d["i"]) or intval($d["i"]) == 0) {
		echo $errorMsg;
		return false;
	}
	
	if (!isset($d["o"])) {
		echo $errorMsg;
		return false;
	}
	
	$row = Data_Select(GetTable("UserManager.reset"), Quick_Find([["user", "=", intval($d["i"])]]));
	
	if (count($row) == 0) {
		echo $errorMsg;
		return false;
	}
	
	if (md5($row[0]["id"]) != $d["o"]) {
		echo $errorMsg;
		return false;
	}
		
	if ($row[0]["oldvalue"] != $d["a"]) {
		echo $errorMsg;
		return false;
	}
		
	if ($row[0]["newvalue"] != $d["b"]) {
		echo $errorMsg;
		return false;
	}
	
	if (strtotime($row[0]["addTime"]) > strtotime('-2 hours')) {
		Data_Delete(GetTable("UserManager.reset"), Quick_Find([["id", "=", $row[0]["id"]]]));
		echo $errorMsg;
		return false;
	}
	
	$form = new Form("UserManager_reset_pw_in");
	$password = new Text("password");
	
	$password->character_max = Standards::standard("UserSystem")->config["maxPasswordLength"];
	$password->character_min = Standards::standard("UserSystem")->config["minPasswordLength"];
	$password->placeholder = "New password";
	
	$confirmPassword = new Text("password");
	
	$confirmPassword->placeholder = "Retype password";
	$confirmPassword->character_max = Standards::standard("UserSystem")->config["maxPasswordLength"];
	$confirmPassword->character_min = Standards::standard("UserSystem")->config["minPasswordLength"];
	
	$form->addInput("newPassword", $password);
	$form->addInput("confirmPassword", $confirmPassword);
	
	$form->structure = new Structure(Theme::grid([
		["%newPassword%", "%confirmPassword%"]
	], "UserSystem.login")->get().Theme::input_submit("Set new password", "UserSystem.passwordReset")->get());
	
	$form->on("success", function ($data) use($row) {
		if ($data["newPassword"] != $data["confirmPassword"])
			return Message::QuickError("Passwords do not match.");
		
		$user = Standards::findEntities("UserSystem.User", ["#" => $row[0]["user"]])[0];
		
		$user->setPassword($data["newPassword"]);
		
		$user->save();
		
		Data_Delete(GetTable("UserManager.reset"), Quick_Find([["id", "=", $row[0]["id"]]]));
		
		$msg = Message::QuickSuccess("Password changed.");
		
		return $msg;
	});
	
	$form->check();
	
	echo Theme::container($form->get(), "UserSystem.resetPassword")->get();
});

class UserManager_Widgets_Perms extends Widget {
	function get() {
		if (!Standards::standard("UserSystem")->isLoggedIn()) return;
		if (!Standards::standard("UserSystem")->getLoggedIn()->checkPermission("UserSystem.perms.edit")) return "No permission";

		$view = new Control_Structure([
			"type" => 's',
			"table" => "UserManager.perms",
			"viewOnStart" => false,
			"view" => new UserManager_Perm_View(),
			"edits" => [],
			"canDelete" => true
		]);
		
		$view->on("delete", function ($data) {
			$usr = Standards::standard("UserSystem")->getUserFromId($data["user"]);
			if ($usr !== false) {
				$usr->removeFromGroup($data["group"]);
			}
			
			return true;
		});
		
		$view->structure = new Structure("%user%, ".Theme::input_submit("Search", "UserSystem.perm")->get());
		
		$view->addControl("user", new UserManager_User_Id());
		
		$rtn = Theme::container(
			Theme::container($view->get(), "UserSystem.perm.view"),
			"UserSystem.perm.whole"
		);
		
		if (!Standards::standard("UserSystem")->getLoggedIn()->checkPermission("UserSystem.perms.give")) return $rtn->get();
		
		$cs = new Control_Structure([
			"type" => 'c',
			"table" => "UserManager.perms"
		]);
				
		$cs->addControl("user", new UserManager_User_Id());
		$cs->addControl("group", new UserManager_Group_Name());
		
		$cs->on("builder", function ($b, $d) {
			$b->add("status", 2);
		});
		
		$cs->structure = new Structure(
			Theme::grid([[["%user%", 3], ["%group%", 6], [Theme::input_submit("Give", "UserSystem.perms.save")->get(), 3]]], "UserSystem.perms")->get()
		);
		
		$csGot = $cs->get();
		if (gettype($csGot) != "string") $csGot = "";
		$rtn->append(Theme::panel("Add user to group", $csGot, "UserSystem.perm"));
		
		return $rtn->get();
	}
}

class UserManager_User_Id extends Control {
	function get() {
		$inp = new Dictionary(false);
		
		$inp->maxKeys = 1;
		$inp->minKeys = 1;
		
		$inp->database = createProcessLink("us_s_usr", [], false);
		
		$inp->extraPlaceholder = "+Username";
		
		return $inp;
	}
	
	function validate($data, $oldData = null) {
		$username = $data[0];
		$usr = Standards::standard("UserSystem")->getUserFromName($username);
		
		if ($usr === false)
			return "Invalid username.";
	
		return true;
	}
	
	function filter($val, &$finder, $col) {
		$u = Standards::standard("UserSystem")->getUserFromName($val[0]);
		$finder->where("", $col, "=", $u->getId());
	}
	
	function to($d) {
		$u = Standards::standard("UserSystem")->getUserFromName($d[0]);
		return $u->getId();
	}
	
	function from($d) {
		$u = Standards::standard("UserSystem")->getUserFromId($d);
		return $u->getUsername();
	}
}

class UserManager_Widgets_Groups extends Widget {
	function get() {
		if (!Standards::standard("UserSystem")->isLoggedIn()) return;
		if (!Standards::standard("UserSystem")->getLoggedIn()->checkPermission("UserSystem.groups.edit")) return "No permission";

		$view = new Control_Structure([
			"type" => 's',
			"table" => "UserManager.groups",
			"viewOnStart" => true,
			"view" => new UserManager_Group_View(),
			"edits" => ["name" => new UserManager_Group_Name(), "permission" => new UserManager_Group_List()],
			"canDelete" => true
		]);
		
		$view->on("delete", function ($data) {
			Standards::standard("UserSystem")->removeGroup($data["name"]);
			
			return true;
		});
		
		$view->structure = new Structure("%name%, ".Theme::input_submit("Search", "UserSystem.group")->get());
		
		
		$s = new Search();
		$view->addControl("name", $s);
		
		
		$rtn = Theme::container(
			Theme::container($view->get(), "UserSystem.group.view"),
			"UserSystem.group.whole"
		);
		
		if (!Standards::standard("UserSystem")->isLoggedIn()) return $rtn->get();
		if (!Standards::standard("UserSystem")->getLoggedIn()->checkPermission("UserSystem.groups.create")) return $rtn->get();
		
		$cs = new Control_Structure([
			"type" => 'c',
			"table" => "UserManager.groups"
		]);
				
		$cs->addControl("name", new UserManager_Group_Name());
		$cs->addControl("permission", new UserManager_Group_List());
		
		$cs->structure = new Structure(
			Theme::grid([[["%name%", 3], ["%permission%", 6], [Theme::input_submit("Save", "UserSystem.groups.save")->get(), 3]]], "UserSystem.groups")->get()
		);
		$rtn->append(Theme::panel("Create group", $cs->get(), "UserSystem.group"));
		
		return $rtn->get();
	}
}

class UserManager_Group_View extends View {
	function sub($r,$i) {
		$btn = Theme::button("X", "UserSystem.group.remove");
		$btn->addClass("UserManager_group_remove");
		$btn->attr("groupname", $r["name"]);
		$cont = Theme::container(Theme::grid([[[$r["name"], 4], [implode(", ", json_decode($r["permission"])), 6], [$btn->get(), 2]]], "UserSystem.group")->get(), "UserSystem.group");
		$cont->attr("style", "cursor: pointer;");
		$cont->attr("groupid", $r["id"]);
		$cont->addClass("UserManager_group");
		$cont->attr("EditSort", "");
		return $cont->get();
	}
}

class UserManager_Perm_View extends View {
	function sub($r, $i) {
		$cont = Theme::container(Theme::grid([[[Standards::standard("UserSystem")->getUserFromId($r["user"])->getUsername(), 4], [$r["group"], 8]]], "UserSystem.perm")->get(), "UserSystem.perm");
		$cont->attr("style", "cursor: pointer;");
		$cont->attr("EditSort", "");
		if ($r["status"] == 2){
			Theme::tell($cont, 1, "UserSystem.perm");
		}else{
			Theme::tell($cont, 4, "UserSystem.perm");
		}
		return $cont->get();
	}
}
/*
onProcess("u_s_eg", function ($params) {
	if (!UserManager::isLoggedIn()) return;
	if (!UserManager::getLoggedIn()->checkPermission("UserSystem.groups.edit")) return;
	if (!isset($params["i"])) return;
	if (!is_int(intval($params["i"]))) return;
	
	$cs = new Control_Structure([
		"type" => 'e',
		"table" => "UserManager.groups",
		"id" => intval($params["i"])
	]);
	
	$cs->client("submit", "window.parent.UserSystem_Saved();");
	
	$cs->addControl("name", new UserManager_Group_Name());
	$cs->addControl("permission", new UserManager_Group_List());
	
	$cs->on("edit", function ($data, $oldData) {
		if ($oldData["name"] == $data["name"])
			return true;
		
		if (UserManager::getGroup($data["name"]) === false)
			return true;
		
		return false;
	});
	
	$cs->structure = new Structure(
		Theme::grid([[["%name%", 3], ["%permission%", 6], [Theme::input_submit("Save", "UserSystem.groups.save")->get(), 3]]], "UserSystem.groups")->get()
	);
	Page("blank.html");
	echo($cs->get());
});
*/
class UserManager_Group_Name extends Control {
	function get() {
		$inp = new Text();
		$inp->character_max = 256;
		
		$inp->placeholder = "Group name";
		
		return $inp;
	}
	
	function from($val) {
		return $val;
	}
	
	function to($val) {
		return $val;
	}
	
	
}

class UserManager_Group_List extends Control {
	function get() {
		$inp = new Input_List();
		
		$txt = new Text();
		$txt->character_max = 256;
		$txt->not = ["[ ]", "Cannot contain spaces."];
		$txt->placeholder = "Permission";
		
		$rmvbtn = Theme::button("X", "UserSystem.group.remove");
		Theme::tell($rmvbtn, 4, "UserSystem.groups");
		$rmvbtn->attr("listremove", true);
		
		$inp->listStructure = new Structure(Theme::grid([[["%perm%", 10], [$rmvbtn->get(), 2]]], "UserSystem.group.permission")->get());
		
		$btn = Theme::button("Add", "UserSystem.group.add");
		$btn->attr("listadd", true);
		Theme::tell($btn, 1, "UserSystem.groups");
		$inp->structure = new Structure("<listarea></listarea>".$btn->get());
		
		$inp->addInput("perm", $txt);
		
		return $inp;
	}
	
	function from($val) {
		$arr = [];
		$decode = json_decode($val);
		foreach ($decode as $p) {
			array_push($arr, ["perm" => $p]);
		}
		return $arr;
	}
	
	function to($val) {
		$arr = [];
		foreach ($val as $v) {
			array_push($arr, $v["perm"]);
		}
		return json_encode($arr);
	}
	
}


class UserManager_Controls_Search extends Control {
	function get() {
		
	}
	
	
}

class UserManager_Widgets_UserBlock extends Widget {
	public $id;
	
	function __construct($id) {
		$this->id = $id;
	}
	
	function get() {
		$st = Standards::standard("UserSystem")->userStructure;
		$users = Standards::findEntities("UserSystem.User.#".$this->id);
		$data = [
			"username" => "Not found!",
			"registerTime" => "",
			"email" => "",
			"id" => -1
		];
		
		if (count($users) > 0) {
			$data = [
				"username" => $users[0]->getUsername(),
				"registerTime" => $users[0]->getRegisterTime(),
				"email" => $users[0]->getEmail(),
				"id" => $users[0]->getId()
			];
		}
		
		return $st->get($data);
	}
}

class UserManager_Widgets_Logout extends Widget {
	public function get() {
		$form = new Form("UserSystem_Logout");
		$form->structure = new Structure(Theme::input_submit("Logout", "UserSystem.logout")->get());

		$none = new Text();
		$none->blank = true;
		$form->addInput("none", $none);
		
		
		$form->on("success", function ($data) {
			Standards::standard("UserSystem")->logout();
			$m = new Message();
			$m->add("form", Message::Action("UserSystem_reload", []));
			return $m;
		});
		
		$rtn = $form->get();
		$form->check();
		
		return $rtn;
	}
}


class UserManager_Widgets_Login extends Widget {
	public $structure;
	static private $id = 0;
	
	public function __construct($structure = false) {
		if ($structure === false) {
			$grid = Theme::grid([["%username%", "%password%"], [["", 10], ["%submit%", 2]]], "UserSystem.login");
			$e = Theme::container($grid->get(), "UserSystem.login");
			$structure = new Structure($e->get());
		}
		
		self::$id++;
		
		$this->structure = $structure;
	}
	
	public function get() {
		$form = new Form("UserSystem_Login_".self::$id);
		$form->structure = new Structure($this->structure->get(["submit" => Theme::input_submit("Login", "UserSystem.login")->get()]));
		
		$handle = new Text();
		$handle->character_min = Standards::standard("UserSystem")->config["minUsernameLength"];
		$handle->character_max = Standards::standard("UserSystem")->config["maxUsernameLength"];
		$handle->placeholder = "username/email";
		
		$form->addInput("username", $handle);
		
		$pw = new Text("password");
		$pw->character_min = Standards::standard("UserSystem")->config["minPasswordLength"];
		$pw->character_max = Standards::standard("UserSystem")->config["maxPasswordLength"];
		$pw->placeholder = "password";
		
		$form->addInput("password", $pw);
		
		$form->client("submit", "
			$(event.\$form).find('.input_error').remove();
		");
		
		$form->client("post", "
			if (event.data === false) return;
			$(event.\$form).append('<div class=\"loading\">".Theme::loader("UserSystem.login")->get()."</div>');
			$(event.\$form).find('input[type=submit]').addClass('disabled').attr('disabled', 'disabled');
		");
		
		$form->client("receive", "
			$(event.\$form).children('.loading').remove();
			$(event.\$form).find('input[type=submit]').removeClass('disabled').removeAttr('disabled');
			$(event.\$form).children('.error, .success').hide(function () {
				$(this).remove();
			});
		");
				
		$form->client("inputError", "
			$(event.\$error).fadeOut(100);
			$(event.\$error).addClass('input_error');
			$(event.\$error).fadeIn(100);
		");
		
		$form->on("error", function ($data) {
			$m = new Message();
			$e = Theme::container("Error", "UserSystem.login.error");
			$e->insert("Wrong username or password");
			Theme::tell($e, 4, "UserSystem.login.error");
			$m->add("form", Message::Error($e->get()));
			return $m;
		});

		$form->on("success", function ($data) {
			Wait(Standards::standard("UserSystem")->config["Login_Wait_Time"]);
			
			if (Standards::standard("UserSystem")->login($data["username"], $data["password"])) {
				$m = new Message();
				$m->add("form", Message::Action("UserSystem_reload", []));
				return $m;
			}else{
				$m = new Message();
				$e = Theme::container("Wrong username or password", "UserSystem.login.error");
				Theme::tell($e, 4, "UserSystem.login.error");
				$m->add("form", Message::Success($e->get()));
				return $m;
			}
		});
		
		$rtn = $form->get();
		$form->check();
		$usersys = Standards::UserSystem();
		return $rtn.Theme::accordion(["Forgot your password?" => Get_Widget(new $usersys->ResetPassword())], "UserSystem.passwordReset")->get();
	}
}


class UserManager_Widgets_Register extends Widget {
	public $structure;
	
	public function __construct($structure = false) {
		if ($structure === false) {
			$e = Theme::container("%username%<br>%email%<br>%password%<br>%confirmpassword%<br><label>".Standards::standard("UserSystem")->config["Register_Message"]."</label><br>%submit%", "UserSystem.register");
			$structure = new Structure($e->get());
		}
		self::$c++;
		$this->structure = $structure;
	}
	
	static public $c = 0;
	
	public function get() {
		$form = new Form("UserSystem_Register_".self::$c);
		$form->structure = new Structure($this->structure->get(["submit" => Theme::input_submit("Register", "UserSystem.register")->get()]));
		
		$handle = new Text();
		$handle->character_min = Standards::standard("UserSystem")->config["minUsernameLength"];
		$handle->character_max = Standards::standard("UserSystem")->config["maxUsernameLength"];
		$handle->only = ["[A-Za-z0-9]", "A-Z 0-9"];
		$handle->placeholder = "Username";
		
		$form->addInput("username", $handle);
		
		$email = new Text();
		$email->character_min = 5;
		$email->character_max = 256;
		$email->placeholder = "Email";
		
		$form->addInput("email", $email);
		
		$pw = new Text("password");
		$pw->character_min = Standards::standard("UserSystem")->config["minPasswordLength"];
		$pw->character_max = Standards::standard("UserSystem")->config["maxPasswordLength"];
		$pw->placeholder = "Password";
		
		$form->addInput("password", $pw);
		
		$cpw = new Text("password");
		$cpw->character_min = Standards::standard("UserSystem")->config["minPasswordLength"];
		$cpw->character_max = Standards::standard("UserSystem")->config["maxPasswordLength"];
		$cpw->placeholder = "Retype Password";
		
		$form->addInput("confirmpassword", $cpw);
		
		$form->client("submit", "
			$(event.\$form).find('.input_error').remove();
		");
		
		$form->client("post", "
			if (event.data === false) return;
			$(event.\$form).append('<div class=\"loading\">".Theme::loader("UserSystem.login")->get()."</div>');
			$(event.\$form).find('input[type=submit]').addClass('disabled').attr('disabled', 'disabled');
		");
		$form->client("receive", "
			$(event.\$form).children('.loading').remove();
			$(event.\$form).find('input[type=submit]').removeClass('disabled').removeAttr('disabled');
			$(event.\$form).children('.error, .success').hide(function () {
				$(this).remove();
			}, 5000);
		");
		
				
		$form->client("inputError", "
			$(event.\$error).fadeOut(100);
			$(event.\$error).addClass('input_error');
			$(event.\$error).fadeIn(100);
		");
		
		$form->on("error", function ($data) {
			$m = new Message();
			$e = Theme::container("Error", "UserSystem.register.error");
			$e->insert("Wrong username or password");
			Theme::tell($e, 4, "UserSystem.register.error");
			$m->add("form", Message::Error($e->get()));
			return $m;
		});

		$form->on("success", function ($data) {
			Wait(Standards::standard("UserSystem")->config["Sign_Up_Wait_Time"]);
			
			$m = new Message();
			$e = Theme::container("Error ", "UserSystem.register.error");
			//$e->attr("style", "color: aliceblue");
			Theme::tell($e, 4, "UserSystem.register.error");
			
			if ($data["password"] != $data["confirmpassword"]) {
				$e->insert("Passwords do not match");
				$m->add("form", Message::Error($e->get()));
				return $m;
			}
			
			if (filter_var($data["email"], FILTER_VALIDATE_EMAIL) === false) {
				$e->insert("Invalid email");
				$m->add("form", Message::Error($e->get()));
				return $m;
			}
			
			$msg = Standards::standard("UserSystem")->registerUser($data["username"], $data["email"], $data["password"]);
			
			if ($msg === STANDARD_USER_SYSTEM_USERNAME_TAKEN) {
				$e->insert("Username already taken");
				$m->add("form", Message::Error($e->get(), 25));
				return $m;
			}
			
			if ($msg === STANDARD_USER_SYSTEM_EMAIL_TAKEN) {
				$e->insert("Email already in use");
				$m->add("form", Message::Error($e->get(), 25));
				return $m;
			}
			
			if ($msg === STANDARD_USER_SYSTEM_ACCOUNT_NOT_CONFIRMED) {
				$e->insert("Please make sure to confirm your account.");
				$m->add("form", Message::Error($e->get(), 25));
				return $m;
			}
			
			if ($msg === false) {
				$e->insert("Error. Please try again later.");
				$m->add("form", Message::Error($e->get(), 25));
				return $m;
			}
			
			if ($msg === true) {
				$msga = new Message();
				$s = Theme::container("", "UserSystem.register.success");
				$s->insert("Great! Now all you need to do is check ".$data["email"]." and confirm it.");
				$msga->add("form", Message::Success($s->get(), 10000));
				return $msga;
			}
		});
		
		$rtn = $form->get();
		$form->check();
		
		return $rtn;
	}
}


//Actions
class UserManager_Actions_Reload extends Action {
	public $name = "UserSystem_reload";
	
	function javascript() {
		return '
			location.reload(true);
		';
	}
}

onProcess("us_e_cncl", function ($p) {
	Wait(3);
	
	if (!isset($p["z"])) {
		Go("index.php");
		return;
	}
	
	if (!isset($p["h"])) {
		Go("index.php");
		return;
	}
	
	if (!isset($p["c"])) {
		Go("index.php");
		return;
	}
	
	if (!isset($p["i"])) {
		Go("index.php");
		return;
	}
	
	$id = intval($p["z"]);
	
	$found = Data_Select(GetTable("UserManager.reset"), Quick_Find([["id", "=", $id]]));
	if (count($found) == 0) {
		Go("index.php");
		return;
	}
	
	if ($found[0]["type"] != STANDARD_USER_SYSTEM_EMAIL_CHANGE) {
		Go("index.php");
		return;
	}
	
	$user = Standards::findEntities("UserSystem.User", ["#" => intval($p["i"])]);
	if (count($user) == 0) {
		Go("index.php");
		return;
	}
	
	if ($p["h"] != $found[0]["hash"]) {
		Go("index.php");
		return;
	}
	
	if ($p["c"] != $found[0]["oldvalue"]) {
		Go("index.php");
		return;
	}
	
	$builder2 = new Data_Builder();
	$builder2->add("done", 1);
	Data_Update(GetTable("UserManager.reset"), $builder2, Quick_Find([["id", "=", $found[0]["id"]]]));
	
	if ($found[0]["done"] == 1) {
		$oldEmails = Standards::findEntities("UserSystem.User", ["=" => ["email" => $found[0]["oldvalue"]]]);
		
		if (count($oldEmails) > 0) {
			$msg = Theme::container("The email ".$found[0]["oldemail"]." is already in use.", "UserSystem.error");
			Theme::tell($msg, 4, "UserSystem.error");
			echo $msg->get();
			return;
		}
		
		$builder = new Data_Builder();
		$builder->add("email", $found[0]["oldvalue"]);
		Data_Update(GetTable("UserManager.users"), $builder, Quick_Find([["id", "=", intval($p["i"])]]));
		
		$msg = Theme::container("Email changed back to ".$found[0]["oldemail"].".", "UserSystem.success");
		Theme::tell($msg, 1, "UserSystem.success");
		echo $msg->get();
		return;
	}
	
	$msg = Theme::container("Email change request canceled.", "UserSystem.success");
	Theme::tell($msg, 1, "UserSystem.success");
	echo $msg->get();
});

onProcess("us_e_cnfrm", function ($p) {
	Wait(3);
	
	$ok = true;
	if (!isset($p["x"])) {
		Go("index.php");
		return;
	}
	
	if (!isset($p["h"])) {
		Go("index.php");
		return;
	}
	
	if (!isset($p["n"])) {
		Go("index.php");
		return;
	}
	
	if (!isset($p["c"])) {
		Go("index.php");
		return;
	}
	
	if (!isset($p["i"])) {
		Go("index.php");
		return;
	}
	
	$id = intval($p["x"]);
	
	$found = Data_Select(GetTable("UserManager.reset"), Quick_Find([["id", "=", $id]]));
	if (count($found) == 0) {
		Go("index.php");
		return;
	}
	
	if ($found[0]["type"] != STANDARD_USER_SYSTEM_EMAIL_CHANGE) {
		Go("index.php");
		return;
	}
	
	if ($found[0]["done"] == 1) {
		$msg = Theme::container("Email change was canceled by ".$found[0]["oldvalue"].".", "UserSystem.error");
		Theme::tell($msg, 4, "UserSystem.error");
		echo $msg->get();
		return;
	}
	
	$user = Standards::findEntities("UserSystem.User", ["#" => intval($p["i"])]);
	if (count($user) == 0) {
		Go("index.php");
		return;
	}
	
	$oldEmails = Standards::findEntities("UserSystem.User", ["=", ["email", $found[0]["newemail"]]]);
	
	if (count($oldEmails) > 0) {
		$bldy = new Data_Builder();
		$bldy->add("done", 1);
		Data_Update(GetTable("UserManager.reset"), $bldy, Quick_Find([["id", "=", $found[0]["id"]]]));
		
		$msg = Theme::container("The email ".$found[0]["newemail"]." is already in use.", "UserSystem.error");
		Theme::tell($msg, 4, "UserSystem.error");
		echo $msg->get();
		return;
	}
	
	if ($user[0]->getEmail() != $found[0]["oldvalue"]) {
		Go("index.php");
		return;
	}
	
	if ($p["h"] != $found[0]["hash"]) {
		Go("index.php");
		return;
	}
	
	if ($p["n"] != $found[0]["newvalue"]) {
		Go("index.php");
		return;
	}
	
	if ($p["c"] != $found[0]["oldvalue"]) {
		Go("index.php");
		return;
	}
	
	$builder = new Data_Builder();
	$builder->add("email", $found[0]["newvalue"]);
	Data_Update(GetTable("UserManager.users"), $builder, Quick_Find([["id", "=", intval($p["i"])]]));
	
	$builder2 = new Data_Builder();
	$builder2->add("done", 1);
	Data_Update(GetTable("UserManager.reset"), $builder2, Quick_Find([["id", "=", $found[0]["id"]]]));
	
	$msg = Theme::container("Email successfuly changed.", "UserSystem.success");
	Theme::tell($msg, 1, "UserSystem.success");
	echo $msg->get();
});

onProcess('u_s_cfirm', function ($params){
	Wait(Standards::standard("UserSystem")->config['Confirm_Email_Wait_Time']);
	
	if (md5($params['a']) != $params['i']) return;
	
	$user = Standards::standard("UserSystem")->getUserFromId($params['a']);
	if ($user === false) {
		echo "Error";
		return;
	}else{
		if ($user->isConfirmed()) {
			echo "Error";
			return;
		}
	}
	
	
	
	$finder = new Data_Finder();
	$finder->where('', 'id', '=', $params['a']);
	$finder->where('AND', 'confirmed', '=', 0);
	$builder = new Data_Builder();
	$builder->add('confirmed', 1);
	
	Data_Update(GetTable('UserManager.users'), $builder, $finder);
	echo 'Success';
});

function UserManager_Status(){
	return true;
}

function UserManager_Structure () {
	return array(
		'users' => "`username` VARCHAR(256) NOT NULL , `password` VARCHAR(256) NOT NULL , `status` TINYINT NOT NULL , `confirmed` TINYINT NOT NULL , `email` VARCHAR(256) NOT NULL , `registerTime` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP",
		'reset' => '`user` INT NOT NULL , `oldvalue` VARCHAR(256) NOT NULL , `newvalue` VARCHAR(256) NOT NULL , `type` TINYINT NOT NULL , `addTime` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP , `hash` VARCHAR(256) NOT NULL , `done` TINYINT NOT NULL',
		'perms' => '`user` INT NOT NULL , `group` VARCHAR(256) , `giveTime` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP , `status` TINYINT NOT NULL , `removeTime` TIMESTAMP NOT NULL',
		'groups' => '`name` VARCHAR(256) , `permission` TEXT NOT NULL , `addTime` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP'
	);
}

class User_View extends Entity_View {
	function sub($row, $inj) {
		$e = new Element("div", ["style" => "display: inline-block;"]);
		
		$e->insert(Standards::standard("UserSystem")->userStructure->get($row));
		
		$e->prepend($inj->get("top", false, "<br>"));
		$e->append($inj->get("bottom", false, "<br>"));
		
		$e = $inj->align($e);
		
		return $e->get();
	}
}

class User extends Entity implements iUserSystem_User {
	
	static public $template = [
		"username" => "Untitled user",
		"password" => "",
		"email" => "",
		"status" => 2,
		"registerTime" => "",
		"confirmed" => 0
	];
	
	static public $globalTable;
	static public $globalQuery;
	
	static public function doStuff() {
		self::$globalTable = GetTable("UserManager.users");
	
		self::$globalQuery = [
			"#" => [
				"type" => "int",
				"find" => function ($finder, $datas, $mix) {
					$finder->where($mix, "id", "=", $datas);
				}
			],
			"<" => [
				"type" => "string",
				"find" => function ($finder, $val, $mix) {
					if ($val == "time")
						$finder->order("registerTime", "DESC");
				}
			],
			">" => [
				"type" => "string",
				"find" => function ($finder, $val, $mix) {
					if ($val == "time")
						$finder->order("registerTime", "ASC");
				}
			],
			";" => [
				"type" => "string",
				"find" => function ($finder, $val, $mix) {
					if ($val == "confirmed")
						$finder->where($mix, "confirmed", "=", 0);
				}
			],
			"~" => [
				"type" => "string",
				"find" => function ($finder, $val, $mix) {
					if ($val == "confirmed")
						$finder->where($mix, "confirmed", "=", 1);
				}
			],
			"=" => [
				"type" => "pair",
				"find" => function ($finder, $val, $mix) {
					$finder->where($mix, $val[0], "=", $val[1]);
				}
			]
		];
		
	}
	
	private $gotAllGroups;
	
	public function builtTemplate() {
		$this->_data["registerTime"] = date("Y-m-d H:i:s");
	}
	
	public function init() {
		
		
		$gotAllGroups = false;
		
		if (isset(Standards::standard("UserSystem")->userCache[$this->getUsername()]))
			return;
		
		Standards::standard("UserSystem")->userCache[$this->getUsername()] = [$this, []];
	}
	
	//Standard methods
	public function changeUsername($newUsername) {
		if ($newUsername == $this->getUsername())
			return false;
		
		$this->_data["username"] = $newUsername;
	}
	
	public function changeEmail($newEmail, $sendConfirmEmail = true, $sendCancelEmail = true) {
		$found = Standards::findEntities("UserSystem.User", ["=" => ["email", $newEmail]]);
		
		if (count($found) > 0)
			return false;
		
		$hash = md5(rand(100, 999999997));
		
		$builder = new Data_Builder();
		$builder->add("user", $this->getId());
		$builder->add("oldvalue", $this->getEmail());
		$builder->add("newvalue", $newEmail);
		$builder->add("hash", $hash);
		$builder->add("type", STANDARD_USER_SYSTEM_EMAIL_CHANGE);
		$builder->add("done", 0);
		
		$ind = Data_Insert(GetTable("UserManager.reset"), $builder);
		
		if ($ind !== false) {
			if ($sendConfirmEmail) {
				$newMail = new Email(true, "Email confirmation", "Dear ".$this->getUsername().", Please go to this url ".createProcessLink("us_e_cnfrm", ["x" => $ind, "h" => $hash, "n" => $newEmail, "c" => $this->getEmail(), "i" => $this->getId()])." in a web browser to confirm your new account email.");
				$newMail->send([$newEmail]);
			}
			
			if ($sendCancelEmail) {
				$oldMail = new Email(true, "Email change on ".Website_name, "Dear ".$this->getUsername().", Your account ".$this->getUsername()." recently requested an email change. If you wish to cancel this change go to this url ".createProcessLink("us_e_cncl", ["z" => $ind, "h" => $hash, "c" => $this->getEmail(), "i" => $this->getId()])." in a web browser. Please discard this email if you do not own this account.");
				$oldMail->send([$this->getEmail()]);
			}
		}
		
	}
	
	static public function getRawView($injections, $level = 1) {
		return new User_View($injections, $level);
	}
	
	public function getUsername() {
		return $this->_data["username"];
	}
	
	public function getRegisterTime() {
		return $this->_data["registerTime"];
	}
	
	public function getEmail() {
		return $this->_data["email"];
	}
	
	public function checkPassword($plainPassword) {
		if (password_verify($plainPassword, $this->_data["password"]))
			return true;
		return false;
	}
	
	public function getId() {
		return $this->_data["id"];
	}
	
	public function isConfirmed() {
		return ($this->_data["confirmed"] == 0) ? false : true;
	}
	
	public function setPassword($newPassword) {
		$this->_data["password"] = password_hash($newPassword, PASSWORD_DEFAULT);
	}
	
	public function notify($title, $body, $label = "Notification", $sendEmail = true) {
		$ns = Standards::NotificationSystem();
		if ($ns !== false) {
			$noti = new $ns->Notification();
			$noti->setTitle($title);
			$noti->setBody($body);
			$noti->setLabel($label);
			$noti->setUser($this->getId());
			$noti->save();
			if ($sendEmail)
				$noti->email();
		}else{
			$mail = new Email(true, "New notification ".$title, $body);
			
			$mail->send([$this->getEmail()]);
		}
	}
	
	//Groups and permissions
	private function getAllGroups() {
		if ($this->gotAllGroups)
			return Standards::standard("UserSystem")->userCache[$this->getUsername()][1];
		
		$gs = Data_Select(GetTable("UserManager.perms"), Quick_Find([["user", "=", $this->getId()], ["status", "=", 2]]));
		
		foreach ($gs as $group) {
			Standards::standard("UserSystem")->userCache[$this->getUsername()][1][$group["group"]] = $group;
		}
		
		$this->gotAllGroups = true;
		return Standards::standard("UserSystem")->userCache[$this->getUsername()][1];
	}
	
	public function inGroup($name) {
		if (isset(Standards::standard("UserSystem")->userCache[$this->getUsername()][1][$name]))
			if (Standards::standard("UserSystem")->userCache[$this->getUsername()][1][$name]["status"] == 2) {
				return true;//UserManager::$userCache[$this->getUsername()][1][$name];
			}else{
				return false;
			}
		
		$found = Data_Select(GetTable("UserManager.perms"), Quick_Find([["user", "=", $this->getId()], ["status", "=", 2], ["group", "=", $name]]));
		if (count($found) == 0)
			return false;
		
		Standards::standard("UserSystem")->userCache[$this->getUsername()][1][$name] = $found[0];
		
		return true;
		
	}
	
	public function addToGroup($name) {
		if ($this->inGroup($name) OR !Standards::standard("UserSystem")->getGroup($name))
			return false;
		
		$builder = new Data_Builder();
		$builder->add("user", $this->getId());
		$builder->add("group", $name);
		$builder->add("status", 2);
		
		Data_Insert(GetTable("UserManager.perms"), $builder);
		return true;
	}
	
	public function removeFromGroup($name) {
		if (!$this->inGroup($name))
			return false;
		
		$builder = new Data_Builder();
		$builder->add("status", 1);
		$builder->add("removeTime", date("Y-m-d H:i:s"));
		
		Data_Update(GetTable("UserManager.perms"), $builder, Quick_Find([["id", "=", $this->getGroup($name)["id"]]]));
		return true;
	}
	
	public function getGroup($name) {
		if (!$this->inGroup($name))
			return false;
		
		return Standards::standard("UserSystem")->userCache[$this->getUsername()][1][$name];
	}
	
	public function permissionParse($perm, $permCheck) {
		$base = 0;
		$amount = count($perm);
		while ($base < $amount) {
			if ($permCheck[$base] == "*")
				return true;
			
			if ($perm[$base] == $permCheck[$base]) {
				if ($base == $amount-1)
					return true;
				$base++;
				continue;
			}else{
				return false;
			}
		}
		return false;
	}
	
	private function permissionsParse($perm, $perms) {
		$boom = explode(".", $perm);
		
		foreach ($perms as $p) {
			if ($this->permissionParse($boom, explode(".", $p)))
				return true;
		}
		
		return false;
	}
	
	public function checkPermission($perm) {
		$def = Standards::standard("UserSystem")->getGroup("default");
		
		if ($def !== false)
			if ($this->permissionsParse($perm, $def))
				return true;
			
		$all = $this->getAllGroups();
		
		foreach ($all as $g) {
			if ($this->permissionsParse($perm, Standards::standard("UserSystem")->getGroup($g["group"])))
				return true;
		}
		
		return false;
	}
}


onEvent("modulesLoaded", function () {
	User::doStuff();
	
	$um = new UserManager();
	
	$um->config = Config::Get("UserManager_Settings", 'Extra_Data_Stores = "" ; Mysql string, Example: `points` BIGINT NOT NULL
profilePictureStorageDirectory = "/public/Images/Users/"; Where the profile pictures will be put. Make sure the path starts with a / and ends with a /

profilePictureMaxSize = "100000"; 100 kb

maxUsernameLength = "24"
minUsernameLength = "2"

maxPasswordLength = "256"
minPasswordLength = "8"

;Time in seconds
Confirm_Email_Wait_Time = "3"
Sign_Up_Wait_Time = "3"
Login_Wait_Time = "2"

Register_Message = "By registering for an account on this website you agree to the terms of service and privacy policy."

;The variables for the following 2 lines are : %username%, %email%, %confirm_url%
Sign_Up_Email_Subject = "Welcome %username% to '.Websom::$Config["Website_name"].'"
Sign_Up_Email_Body = "<h1>Hello %username%, thanks for signing up with '.Websom::$Config["Website_name"].'</h1><br><p>To confirm your account on '.Websom::$Config["Website_name"].', simply go to this url %confirm_url% in a web browser. Thank you</p><br><br><label>If you did not sign up for '.Websom::$Config["Website_name"].' please discard this message.</label>"
Sign_Up_Email_Sender = "noreply@changethis.soon"

;The variables for the following 2 lines are : %username%, %oldemail%, %newemail%, %cancel_url%
Email_Change_Email_Subject = "Email change on '.Websom::$Config["Website_name"].'"
Email_Change_Email_Body = "<h1>Hello %username%</h1><p>it seems that you have changed your email from %oldemail% to %newemail% if you wish to undo this simply go to this url %cancel_url% in a web browser.</p>"
Email_Change_Email_Sender = "noreply@changethis.soon"', "UserManager");
	
	Standards::registerStandard($um);
	Standards::standard("UserSystem")->loggedIn = Standards::standard("UserSystem")->checkLoggedIn();
});

onEvent("ready", function () {
	//Actions
	Register_Action(new UserManager_Actions_Reload);
});

/*
function UserManager_private_Login($user) {
	unset($user['password_']);
	$_SESSION['UM_CURRENT_USER'] = $user;
}

function UserManager_Logout() {
	unset($_SESSION['UM_CURRENT_USER']);
}

function UM_Check_Permission($userId, $permission) {
	global $groups;
	$finder = new Data_Finder();
	$findGroups = array();
	foreach ($groups as $gName => $perms){
		if (in_array($permission, $perms)) {
			array_push($findGroups, $gName);
		}
	}
	$finder->where('', 'user', '=', $userId);
	$finder->where('AND', 'group', 'IN', '("'.implode('","', $findGroups).'")', true);
	$ok = Data_Select(GetTable('UserManager.perms'), $finder);
	return (count($ok) == 0) ? false : true;
}

function UM_Get_All_Usernames() {
	$valer = array();
	foreach (Data_Select(GetTable('UserManager.users'), new Data_Finder(true, 'username')) as $username) array_push($valer, $username['username']);
	return $valer;
}

function UM_Get_User_Id($username) {
	$finder = new Data_Finder(false, 'id');
	$finder->where('', 'username', '=', $username);
	return Data_Select(GetTable('UserManager.users'), $finder)[0]['id'];
}

function UM_Get_User_Username($id) {
	$finder = new Data_Finder(false, 'username');
	$finder->where('', 'id', '=', $id);
	return Data_Select(GetTable('UserManager.users'), $finder)[0]['username'];
}

onProcess('validate_user', function ($params){
	global $config;
	Wait($config['Confirm_Email_Wait_Time']);
	$finder = new Data_Finder();
	$finder->where('', 'id', '=', $params['u']);
	$finder->where('AND', 'status', '=', 0);
	$builder = new Data_Builder();
	$builder->add('status', 1);
	
	Data_Update(GetTable('UserManager.users'), $builder, $finder);
	echo 'Success';
});

function UM_Get_User (){
	if (isset($_SESSION['UM_CURRENT_USER'])){
		return $_SESSION['UM_CURRENT_USER'][0];
	}else{
		return false;
	}
}

class UM_Create_User extends Widget {
	public $owner = "UserManager";
	public $name = "UM_Create_User";
	public function get() {
		global $config;
		$ds = new Data_Structure("UserManager.users", 'Great now just check your email to confirm and start.');
		
		if (isset($p['usernameHook'])) call_user_func($p['usernameHook'], $ds);
		$ds->addControl(new UM_Username, 'username');
		$pw = new UM_Password;
		if (isset($p['passwordHook'])) call_user_func($p['passwordHook'], $ds);
		$ds->addControl($pw, 'password_');
		if (isset($p['retypePasswordHook'])) call_user_func($p['retypePasswordHook'], $ds);
		$ds->addControl(new UM_Password('Retype password'), 'passwordCheck', true);
		if (isset($p['emailHook'])) call_user_func($p['emailHook'], $ds);
		$ds->addControl(new UM_Email, 'email');
		
		
		if (isset($p['submitHook'])) call_user_func($p['submitHook'], $ds);
		
		$ds->addControl(new Submit);
		
		$ds->onSuccess = function ($values) {
			global $config;
			$isOk = true;
			$finder = new Data_Finder();
			$finder->where('', 'username', '=', $values['username']);
			$foundUser = Data_Find(GetTable('UserManager.users'), $finder);
			if ($foundUser) {
				InputSend(InputError("Sorry but that username is taken."));
				$isOk = false;
			}
			$finder = new Data_Finder();
			$finder->where('', 'email', '=', $values['email']);
			$foundUser = Data_Find(GetTable('UserManager.users'), $finder);
			if ($foundUser) {
				InputSend(InputError("Sorry but that email is already in use."));
				$isOk = false;
			}
			if ($values['password_'] != $values['passwordCheck']) {
				InputSend(InputError("Passwords do not match."));
				$isOk = false;
			}
			
			if ($isOk) {
				Wait($config['Sign_Up_Wait_Time']);
				$builder = new Data_Builder();
				$builder->add('password_', password_hash($values['password_'], PASSWORD_DEFAULT));
				$builder->add('username', $values['username']);
				$builder->add('email', $values['email']);
				$id = Data_Insert(GetTable('UserManager.users'), $builder);
				UM_private_Send_Confirmation($values, $id);
				InputSend(InputSuccess('Great now just check your email to confirm and start.'));
			}
		};
		
		return Data_Input_Plain($ds);
	}
}

function UM_private_Send_Confirmation($values, $id) {
	global $config;
	$link = createProcessLink('validate_user', array('u'=>$id));
	$subject = $config['Sign_Up_Email_Subject'];
	$subject = str_replace('%username%', $values['username'], $subject);
	$subject = str_replace('%email%', $values['email'], $subject);
	$subject = str_replace('%confirm_url%', $link, $subject);
	$body = $config['Sign_Up_Email_Body'];
	$body = str_replace('%username%', $values['username'], $body);
	$body = str_replace('%email%', $values['email'], $body);
	$body = str_replace('%confirm_url%', $link, $body);
	Send_Mail($values['email'], $subject, $body);
}

function UM_private_Send_Message($values, $email, $subject, $body) {
	global $config;
	foreach ($values as $key => $value){
		$body = str_replace('%'.$key.'%', $value, $body);
		$subject = str_replace('%'.$key.'%', $value, $subject);
	}
	var_dump($body);
	Send_Mail($email, $subject, $body);
}

class UM_Change_Password {
	public $owner = 'UserManager';
	public $name = 'UM_Change_Password';
	public function get() {
		$user = UM_Get_User();
		if ($user !== false) {
			$ds = new Data_Structure('UserManager.users', 'Password successfuly changed.', 'Clear');
			if (isset($p['oldPasswordHook'])) call_user_func($p['oldPasswordHook'], $ds);
			$ds->addControl(new UM_Password('Old password'), 'passwordOld', true);
			$pw = new UM_Password('New password');
			$pw->hashPassword = true;
			if (isset($p['newPasswordHook'])) call_user_func($p['newPasswordHook'], $ds);
			$ds->addControl($pw, 'password_');
			if (isset($p['retypePasswordHook'])) call_user_func($p['retypePasswordHook'], $ds);
			$ds->addControl(new UM_Password('Retype new password'), 'passwordCheck', true);
			if (isset($p['changeHook'])) call_user_func($p['changeHook'], $ds);
			$ds->addControl(new UM_Button('Change Password'), 'button', true);
			$ds->onSuccess = function($vals) {
				$user = UM_Get_User();
				InputSend(InputError('Wrong password.'));
				if ($vals['password_'] != $vals['passwordCheck']) {
					InputSend(InputError('Passwords do not match.'));
					return false;
				}
				$finder = new Data_Finder();
				$finder->where('', 'id', '=', $user['id']);
				$userData = Data_Select(GetTable('UserManager.users'), $finder)[0];
				if (!password_verify($vals['passwordOld'], $userData['password_'])) {
					InputSend(InputError('Wrong password.'));
					return false;
				}
				return true;
			};
			return Data_Input_Edit($ds, $user['id'], false);
		}
		return '';
	}
}

onProcess('email_change_cancel', function ($p){
	$finder = new Data_Finder();
	$finder->where('', 'user', '=', $p['u']);
	$finder->where('AND', 'type', '=', 1);
	$data = Data_Select(GetTable('UserManager.reset'), $finder);
	if (count($data) > 0) {
		$data = $data[0];
		$builder = new Data_Builder();
		$builder->add('email', $data['oldvalue']);
		$finderUser = new Data_Finder();
		$finderUser->where('', 'id', '=', $p['u']);
		Data_Update(GetTable('UserManager.users'), $builder, $finderUser);
		Data_Delete(GetTable('UserManager.reset'), $finder);
		echo 'Success!';
	}
});

class UM_Change_Email {
	public $owner = 'UserManager';
	public $name = 'UM_Change_Email';
	public function get() {
		$user = UM_Get_User();
		if ($user !== false) {
			$ds = new Data_Structure('UserManager.users', false, 'Clear');
			$ds->addControl(new UM_Email('New email'), 'email');
			if (isset($p['changeHook'])) call_user_func($p['changeHook'], $ds);
			$ds->addControl(new UM_Button('Change email'), 'button', true);
			$ds->onSuccess = function($vals) {
				$user = UM_Get_User();
				if ($user !== false) {
					global $config;
					$finder = new Data_Finder();
					$finder->where('', 'user', '=', $user['id']);
					$finder->where('AND', 'type', '=', 1);
					Data_Delete(GetTable('UserManager.reset'), $finder);
					$builder = new Data_Builder();
					$builder->add('oldvalue', $user['email']);
					$builder->add('newvalue', $vals['email']);
					$builder->add('type', 1);
					$builder->add('user', $user['id']);
					Data_Insert(GetTable('UserManager.reset'), $builder);
					$values['cancel_url'] = createProcessLink('email_change_cancel', array('u' => $user['id']));
					$values['oldemail'] = $user['email'];
					$values['newemail'] = $vals['email'];
					UM_private_Send_Message($values, $user['email'], $config['Email_Change_Email_Subject'], $config['Email_Change_Email_Body']);
					return true;
				}
				return false;
			};
			return Data_Input_Edit($ds, $user['id'], false);
		}
		return '';
	}
}

class UM_Login extends Widget {
	public $owner = "UserManager";
	public $name = "UM_Login";
	public function get() {
		global $config;
		$ds = new Data_Structure("UM_Login");
		//if ($p['handleHook'] !== null) call_user_func($p['handleHook'], $ds);
		$ds->addControl(new UM_Login_Handle, 'handle');
		//if ($p['passwordHook'] !== null) call_user_func($p['passwordHook'], $ds);
		$ds->addControl(new UM_Login_Password, 'password');
		//if ($p['loginHook'] !== null) call_user_func($p['loginHook'], $ds);
		$ds->addControl(new UM_Button('Login'));
		
		$ds->onSuccess = function ($vals) {
			global $config;
			Wait($config['Login_Wait_Time']);
			$userSearch = ((filter_var($vals['handle'], FILTER_VALIDATE_EMAIL) !== false) ? 'email' : 'username');
			$finder = new Data_Finder();
			$finder->where('', $userSearch, '=', $vals['handle']);
			$finder->where('AND', 'status', '<>', 0);
			$user = Data_Select(GetTable('UserManager.users'), $finder);
			
			if (count($user) > 0) {
				if (password_verify($vals['password'], $user[0]['password_'])) {
					UserManager_private_Login($user);
					InputSend(InputRefresh());
					
				}else{
					InputSend(InputError('Wrong '.$userSearch.' or password.'));
				}
			}else{
				InputSend(InputError('Wrong '.$userSearch.' or password.'));
			}
		};
		
		return Data_Input_Plain($ds);
	}
}

class UM_Logout extends Widget {
	public $owner = "UserManager";
	public $name = "UM_Logout";
	public function get() {
		global $config;
		$ds2 = new Data_Structure("UM_Logout");
		$ds2->addControl(new UM_Button('Logout'));
		$ds2->onSuccess = function ($v) {
			UserManager_Logout();
			InputSend(InputRefresh());
		};
		
		return Data_Input_Plain($ds2);
	}
}

class UM_User_View extends Widget {
	function __construct ($_id) {
		$this->id = $_id;
	}
	public $id = 0;
	public $owner = "UserManager";
	public $name = "UM_Logout";
	public function get() {
		$finder = new Data_Finder();
		$finder->where('', 'id', '=', $this->id);
		$user = Data_Select(GetTable('UserManager.users'), $finder)[0];
		return '<div style="display: inline-block;" class="UM_User"><img style="display: inline-block;width: 48px;" src="https://encrypted-tbn1.gstatic.com/images?q=tbn:ANd9GcTiqknWpiz-8A1Vd0i7kDSfSPCRz8MOkF3m0MbRpICuRFOsxecvB4-LU5s"><label>'.$user['username'].'</label></div>';
	}
}

class UM_Login_Handle extends Control {
	public $owner = "UserManager";
	public $name = "UM_Login_Handle";
	public function get() {
		global $config;
		$c['type'] = 'text';
		$c['count'] = '1 '.$config['Max_Username_Length'];
		$c['only'] = '@ . _ - a b c d e f g h i j k l m n o p q r s t u v w x y z A B C D E F G H I J K L M N O P Q R S T U V W X Y Z 1 2 3 4 5 6 7 8 9 0';
		$c['placeholder'] = 'Username or email';
		return $c;
	}
}

class UM_Button extends Control {
	public function __construct ($val = 'Ok') {
		$this->text = $val;
	}
	public $text = 'Ok';
	public $owner = "UserManager";
	public $name = "UM_Button";
	public function get() {
		global $config;
		$c['type'] = 'submit';
		$c['value'] = $this->text;
		return $c;
	}
}

class UM_Login_Password extends Control {
	public function __construct ($check = 'Password'){
		$this->placeholder = $check;
	}
	public $owner = "UserManager";
	public $name = "UM_Password";
	private $placeholder = 'Password';
	public function get() {
		global $config;
		$c['type'] = 'password';
		$c['count'] = '1 '.$config['Max_Password_Length'];
		$c['placeholder'] = $this->placeholder;
		return $c;
	}
}

class UM_Username extends Control {
	public $owner = "UserManager";
	public $name = "UM_Username";
	public function get() {
		global $config;
		$c['type'] = 'text';
		$c['count'] = $config['Min_Username_Length'].' '.$config['Max_Username_Length'];
		$c['only'] = 'a b c d e f g h i j k l m n o p q r s t u v w x y z A B C D E F G H I J K L M N O P Q R S T U V W X Y Z 1 2 3 4 5 6 7 8 9 0';
		$c['placeholder'] = 'Username';
		return $c;
	}
}

class UM_Password extends Control {
	public function __construct ($check = 'Password'){
		$this->placeholder = $check;
	}
	public $hashPassword = false;
	private $placeholder = 'Password';
	function get() {
		global $config;
		$c['type'] = 'password';
		$c['count'] = $config['Min_Password_Length'].' '.$config['Max_Password_Length'];
		$c['only'] = 'a b c d e f g h i j k l m n o p q r s t u v w x y z A B C D E F G H I J K L M N O P Q R S T U V W X Y Z 1 2 3 4 5 6 7 8 9 0 ! @ # $ % ^ & *';
		$c['placeholder'] = $this->placeholder;
		return $c;
	}
	function filter($val) {
		if ($this->hashPassword)
			return password_hash($val, PASSWORD_DEFAULT);
		return $val;
	}
}

class UM_Email extends Control {
	public function __construct ($val = 'Email') {
		$this->text = $val;
	}
	public $text = 'Email';
	public $owner = "UserManager";
	public $name = "UM_Email";
	public function get() {
		$c['type'] = 'email';
		$c['count'] = '5 512';
		$c['placeholder'] = $this->text;
		return $c;
	}
}

*/
?>