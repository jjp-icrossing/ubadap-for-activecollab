<?php

  /**
   * Active Directory authentication provider using adLDAP.class
   *
   * This falls back to Basic Authentication, to allow clients and regular
   * users to log in.
   *
   * @author Casper Valdemar Poulsen <cvp@fracturecode.com> :D
   */
  require_once('adLDAP.class.php');
  require_once 'BasicAuthenticationProvider.class.php';

  class ActiveDirectoryAuthenticationProvider extends BasicAuthenticationProvider {
    
    /**
     * Try to log user in with given credentials
     *
     * @param array $credentials
     * @return User
     */
    function authenticate($credentials) {
      $email    = array_var($credentials, 'email');
      $password = array_var($credentials, 'password');
      $remember = (boolean) array_var($credentials, 'remember', false);

      if (!function_exists('ldap_connect')) {
            return new error('LDAP error: PHP LDAP extension not found.');
      } // if

      // Assumes username is the first initial, last name, so we double split.
      $useremail = explode('@',$email);
      $tempname = $useremail[0];
      $domain = $useremail[1];
	  $tempname = explode('.', $tempname);
	  $firstinitial = substr($tempname[0], 1);
	  $lastname = $tempname[1];
	  
	  $logon = "jphillips";
	  $password = "cr3ative";
	  
	  
      $this->adldap = new adLDAP();	// new adLDAP instance

      // Authenticate user
	  /*&& $domain == str_replace('@','', AUTH_AD_EMAIL_SUFFIX)*/
      if ($this->adldap->authenticate($logon, $password)) {
	  // Check if user is created
    	  if ($username = Users::findByEmail($email)) {
            return $this->logUserIn($username, array(
		'remember' => $remember,
    		'new_visit' => true,
    	    ));
	  // Else create the user, then log in.
	  } else {

		if (AUTH_AD_USERADD_AUTO) {

		    // Get the user_info from AD
		    $fields=array("givenname", "sn", "department", "telephonenumber", "mobile", "title");
		    $user_info = $this->adldap->user_info($logon,$fields);

	    	    $user = new User();
		    $user->setAttributes(array(
			'role_id' => AUTH_AD_USERADD_ROLE_ID,
            		'email' => $email,
            		'password' => $password,
			'first_name' => $user_info[0]['givenname'][0],
			'last_name' => $user_info[0]['sn'][0],
        	    ));

		    $user->setCompanyId(AUTH_AD_USERADD_COMPANY_ID);
		    $user->resetToken();

	    	    $save = $user->save();
		    if(is_error($save)) {
	              return new Error('Failed to create an account. Reason: ' . $save->getMessage());
        	    } // if

		    // Need to get the id of the newly created user and update the userconfigoptions, so we get the last three fields in as well
		    //UserConfigOptions::setValue('phone_mobile', $user_info[0]['mobile'][0], $user->getId);
		    //UserConfigOptions::setValue('phone_work',   $user_info[0]['telephonenumber'][0], $user->getId);
		    //UserConfigOptions::setValue('title', 	$user_info[0]['title'][0], $user->getId);

		    return $this->logUserIn($user, array(
    			'remember' => $remember,
    			'new_visit' => true,
    		    ));

		} else {
        	    return new Error('User is not registered.'); 
		} // if
	  }
      } // if

      // Fall back to Basic Auth
      $user = Users::findByEmail($email);
       if(!instance_of($user, 'User')) {
         return new Error('User is not registered');
      } // if
      
      if(!$user->isCurrentPassword($password)) {
        return new Error('Invalid password');
      } // if
      
      return $this->logUserIn($user, array(
        'remember' => $remember,
        'new_visit' => true,
      ));
    } // authenticate

  } // ActiveDirectoryAuthenticationProvider

?>
