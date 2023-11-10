#file:LdapJwtSSO
#--------------------------
  package LdapJwtSSO;
  
  use strict;
  use warnings;
  use Data::Dumper;
  use Net::LDAP;
  use Crypt::JWT qw(encode_jwt decode_jwt);

  use APR::Table ();  
  use Apache2::RequestRec ();
  use Apache2::Request ();
  use Apache2::RequestIO ();
  use Apache2::Connection ();
  use Apache2::RequestUtil ();
  use Apache2::Cookie ();
  
  use Apache2::Const -compile => qw(FORBIDDEN OK REDIRECT);

  my $CONFIG = "/perl_mods/config.txt";
  my $config = read_config($CONFIG);
  my $LDAP_HOST= $config->{'LDAP_HOST'} || ''; #This is passed to Net::LDAP->new, so encode ldap/ldaps and port info in it if necessary
  my $LDAP_BASE = $config->{'LDAP_BASE'} || '';
  my $ANONYMOUS_BIND_FLAG = $config->{'ANONYMOUS_BIND_FLAG'} || '';# "True" or "False"; if "True" will anonymous bind to get DN for user with username/id of $USER
  my $START_TLS_FLAG = $config->{'START_TLS_FLAG'} || ''; # "True" or "False"; if "True" will call start_tls and pass values for following 2 params if specified
  my $START_TLS_VERIFY = $config->{'START_TLS_VERIFY'} || ''; #Value for "verify" param of start_tls, "none", "optional", or "require"
  my $START_TLS_VERSION = $config->{'START_TLS_VERSION'} || ''; #Version of SSL/TLS to use, "sslv1", "sslv3", "tlsv1", "tlsv1_1_, or "tlsv1_2"
  my $CAFILE = $config->{'CAFILE'} || ''; #cafile param to start_tls if not undefined or empty
  my $CAPATH = $config->{'CAPATH'} || ''; #capath param to start_tls if not undefined or empty
  my $FILTER = $config->{'FILTER'} || ''; #filter regex used for anonymous bind (note this is single quoted but has interpolated variables --- they will be interpolated later, so keep this sinqle quoted).
  my $USER_DN = $config->{'USER_DN'} || ''; #regex used to construct user DN when no anonymous bind (note this is single quoted but has interpolated variables --- they will be interpolated later, so keep this sinqle quoted).
  my $DEBUG = $config->{'DEBUG'} || ''; #extra messages/info will be printed if "True"
  my $SESSION_COOKIE_NAME = $config->{'SESSION_COOKIE_NAME'} || ''; #"SSO_SESSION";
  my $SESSION_COOKIE_DOMAIN = $config->{'SESSION_COOKIE_DOMAIN'} || ''; #".mycompany.com";
  my $SESSION_COOKIE_PATH = $config->{'SESSION_COOKIE_PATH'} || ''; #"/";
  my $JWT_ALG = $config->{'JWT_ALG'} || 'HS256'; #HS256
  my $JWT_SECRET = $config->{'JWT_SECRET'} || 'secretJWTkey'; #'secretJWTkey';
  my $JWT_TTL = $config->{'JWT_TTL'} || ''; #8 * 60 * 60; #8 hours, same as SiteMinder cookies in BMS

  sub handler {
      my $r = shift;

      my $req = Apache2::Request->new($r);
      my $username = $req->param("username");
      my $password = $req->param("password");
      my $target = $req->param("target");
      my $action = $req->param("a");
      if (empty($action)) { $action = "login"; } #legal vals are "login" and "validate"
      if (($action ne "login") && ($action ne "validate")) { $action = "login"; } #assume "login" if invalid value

      my $j = Apache2::Cookie::Jar->new($r);
      my $encodedJwtCookie = $j->cookies($SESSION_COOKIE_NAME);
      my $encodedJwt;
      if (defined($encodedJwtCookie)) {
	  $encodedJwt = $encodedJwtCookie->value;
      }

      if (!empty($encodedJwt)) {
	  my ($resCode,$decodedJwt,$mesgTxt) = validateJWT($encodedJwt);
	  if ($resCode) {
	      map { if (empty($decodedJwt->{$_})) { $decodedJwt->{$_} = ""; } } ("username","cn","mail","dn","create_time");
	      if ($action eq "validate") {
		  $r->content_type('text/plain');
		  $r->print("Success\n");
		  $r->print("User=" . $decodedJwt->{'username'} . "\n");
		  $r->print("FullName=" . $decodedJwt->{'cn'} . "\n");
		  $r->print("Email=" . $decodedJwt->{'mail'} . "\n");
		  $r->print("UserDN=" . $decodedJwt->{'dn'} . "\n");
		  my $ttl = 0;
		  if (!empty($decodedJwt->{'exp'})) {
		      $ttl = $decodedJwt->{'exp'} - time;
		  }
		  $r->print("TTL=" . $ttl  . "\n");
		  $r->print("${SESSION_COOKIE_NAME}=" . $encodedJwt . "\n");
		  return Apache2::Const::OK;
	      } else {
		  if (!empty($target)) {
		      $r->headers_out->set(Location => uri_decode($target));
		      return Apache2::Const::REDIRECT;
		  } else {
		      $r->content_type('text/plain');
		      $r->print("$mesgTxt\n" . Dumper($decodedJwt) . "\n");
		      return Apache2::Const::OK;
		  }
	      }
	  } elsif ($action eq "validate") {
	      my $backHereUrl = uri_encode("/sso?a=validate");
	      $r->headers_out->set(Location => "/sso?a=login&target=${backHereUrl}");
	      return Apache2::Const::REDIRECT;
	  }
      }

      if (!empty($username) && !empty($password)) {
	  #$r->print("username = $username\npassword = $password\n");
	  my ($loginRes, $userLdapInfo, $loginResTxt) = checkLogin($username, $password);
	  if ($loginRes) {
	      if (!empty($target)) {
		  setNewJWT($r,$username,$userLdapInfo,$SESSION_COOKIE_NAME,$SESSION_COOKIE_DOMAIN,$SESSION_COOKIE_PATH,1);
	      } else {
		  setNewJWT($r,$username,$userLdapInfo,$SESSION_COOKIE_NAME,$SESSION_COOKIE_DOMAIN,$SESSION_COOKIE_PATH,0);
	      }
	  }
	  if (!$loginRes || empty($target)) {
	      $r->content_type('text/plain');
	      print "$loginResTxt\n";
	      return Apache2::Const::OK;	      
	  } else {
	      $r->headers_out->set(Location => uri_decode($target));
	      return Apache2::Const::REDIRECT;
	  }
      } else {
	  $r->content_type('text/html');
	  if ($action eq "validate") {
	      $target = uri_encode("/sso?a=validate");
	  }
	  my $login_form_html = getLoginFormHtml($target);
	  $r->print($login_form_html);
	  return Apache2::Const::OK;
      }
  
  }

sub validateJWT {

    my ($encodedJwt) = @_;

    my $decodedJwt;
    eval {
	$decodedJwt = decode_jwt(token=>$encodedJwt, key=>$JWT_SECRET);
    };
    if ($@) {
	return(0,undef,"Error decoding JWT: $@\n");
    } else {
	return(1,$decodedJwt,"Successfully Decoded JWT\n");
    }

}

sub setNewJWT {

    my ($r,$username, $userLdapInfo, $name, $domain, $path, $errHeadersFlag) = @_;

    my $curTime = time;
    my $valToEncode = { "username" => $username, "create_time" => $curTime };
    my %withLdapInfo = (%$userLdapInfo, %$valToEncode);
    my $encodedJwt = encode_jwt(payload=>\%withLdapInfo, alg=>$JWT_ALG, key=>$JWT_SECRET, relative_exp => $JWT_TTL);

    my $c_out = Apache2::Cookie->new($r,
				     -name  => $name,
				     -domain => $domain,
				     -path => $path,
				     -value => $encodedJwt );
    if ($errHeadersFlag) {
	$r->err_headers_out->add('Set-Cookie' => $c_out);
    } else {
	$r->headers_out->add('Set-Cookie' => $c_out);
    }

}

sub checkLogin {

    my ($USER, $PWD) = @_;

    my $res_code;
    my $user_dn;
    my $ldap = ldap_connect($LDAP_HOST);
    if (!empty($ANONYMOUS_BIND_FLAG) && ($ANONYMOUS_BIND_FLAG eq 'True')) {
	($res_code,$user_dn) = get_user_dn_anonymous_bind($ldap, $LDAP_BASE, $USER);
    } else {
	($res_code,$user_dn) = get_user_dn($USER);
    }

    if (!$res_code) {
	return(0,undef, "Error getting user DN: $user_dn\n");
    }

    my $mesg = $ldap->bind( $user_dn, password => $PWD );
    if (!empty($DEBUG) && ($DEBUG eq 'True')) {
	print STDERR "non-anonymous bind mesg:\n" . Dumper($mesg) . "\n\n";
    }
    if ( $mesg and $mesg->code() == 0 ) {
	my ($filt_res_code, $filterTxt) = get_filter($USER);
	if (!$filt_res_code) {
	    return(0,undef,"Successful authentication, but error getting filter to search for user entry after bind: " . $filterTxt);
	}
	my $search = $ldap->search(base => "$LDAP_BASE",
				   scope => "subtree",
				   filter => $filterTxt);
	if (!empty($DEBUG) && ($DEBUG eq 'True')) {
	    print STDERR "search (after non-anonymous bind):\n" . Dumper($search) . "\n\n";
	}
	# Check for errors
	if ($search->code() || $search->count() > 1) {
	    return(0,undef,"Successful authentication, but error getting user entry: " . $search->error());
	}
	if ($search->count() > 1) {
	    return(0,undef,"Successful authentication, but error getting user entry: more than one match");
	}
	if ( ! $search->count()) {
	    return(0,undef,"Successful authentication, but error getting user entry: No matches");
	}
	my $user_entry = $search->pop_entry();
	if (!empty($DEBUG) && ($DEBUG eq 'True')) {
	    print "user_entry (non-anonymous bind query):\n". Dumper($user_entry) . "\n\n";
	}
	my $user_dn_from_search = $user_entry->dn;	
	my $user_cn = $user_entry->get_value('cn') || "";
	my $user_mail = $user_entry->get_value('mail') || "";
	$ldap->unbind();	
	return (1,{"dn" => $user_dn_from_search, "cn" => $user_cn, "mail" => $user_mail},"Successful Authentication for user ${USER}\n");	
    } else{
	$ldap->unbind();
	return (0,undef,"Unsuccessful Authentication for user ${USER}\n" . 'Received error ' . $mesg->code() . ': ' . $mesg->error() . "\n");	
    }
}

sub ldap_connect {

    my ($host_uri) = @_;

    my $ldap = Net::LDAP->new($host_uri);
    if (!empty($DEBUG) && ($DEBUG eq 'True')) {
	print "ldap:\n" . Dumper($ldap) . "\n\n";
    }
    my ($tls_res_code, $tls_errmsg) = start_tls($ldap);

    if (!$tls_res_code) {
	die "Error in ldap_connect: " . $tls_errmsg;
    }

    return($ldap);

}

sub get_user_dn_anonymous_bind {

    my ($ldap, $base, $uid) = @_;

    my $ldap_msg = $ldap->bind;
    if (!empty($DEBUG) && ($DEBUG eq 'True')) {
	print "ldap_msg:\n" . Dumper($ldap_msg) . "\n\n";
    }
    
    # Check for errors
    return (0, $ldap_msg->error()) if ($ldap_msg->code);

    my ($filt_res_code, $filterTxt) = get_filter($uid);
    if (!$filt_res_code) {
	return (0,"Error getting filter to search for user entry after bind: " . $filterTxt);
    }
    my $search = $ldap->search(base => "$LDAP_BASE",
			       scope => "subtree", 
			       filter => $filterTxt);
    
    if (!empty($DEBUG) && ($DEBUG eq 'True')) {
	print STDERR "search (after anonymous bind):\n" . Dumper($search) . "\n\n";
    }
    # Check for errors
    return (0, $search->error()) if ($search->code() || $search->count() > 1);
    return (0, "Error: more than one match") if ($search->count() > 1);
    return (0, "Error: No matches") if ( ! $search->count());
    my $user_entry = $search->pop_entry();
    if (!empty($DEBUG) && ($DEBUG eq 'True')) {
	print "user_entry:\n". Dumper($user_entry) . "\n\n";
    }
    my $user_dn = $user_entry->dn;
    if (!empty($DEBUG) && ($DEBUG eq 'True')) {
	print "user_dn:\n" . $user_dn . "\n\n";
    }
    # Return the DN
    return (1, $user_dn);
}

#Used in above function get_user_dn_anonymous_bind to get the filter for the ldap search
sub get_filter {

    my ($uid) = @_;

    #See here for where I got this: https://stackoverflow.com/questions/57812884/perl-is-it-possible-to-have-interpolated-variables-when-a-string-is-read-from
    my $ret_string = eval qq{"$FILTER"};
    return(1,$ret_string);

}

#$user_dn = get_user_dn($USER);
sub get_user_dn {

    my ($uid) = @_;

    #See here for where I got this: https://stackoverflow.com/questions/57812884/perl-is-it-possible-to-have-interpolated-variables-when-a-string-is-read-from
    my $ret_string = eval qq{"$USER_DN"};
    return(1,$ret_string);

}

sub start_tls {

    my ($ldap) = @_;

    if (!empty($START_TLS_FLAG) && ($START_TLS_FLAG eq 'True')) {
	my $tls_args = {};
	if (!empty($START_TLS_VERIFY)) { $tls_args->{'verify'} = $START_TLS_VERIFY; }
	if (!empty($START_TLS_VERSION)) { $tls_args->{'sslversion'} = $START_TLS_VERSION; }
	if (!empty($CAFILE)) { $tls_args->{'cafile'} = $CAFILE; }
	if (!empty($CAPATH)) { $tls_args->{'capath'} = $CAPATH; }
	my $tls_msg = $ldap->start_tls( %$tls_args );
	if (!empty($DEBUG) && ($DEBUG eq 'True')) {
	    print "tls_msg:\n" . Dumper($tls_msg) . "\n\n";
	}
	if ($tls_msg->code()) {
	    return(0,"Error doing start_tls: " . $tls_msg->error());
	}
    }
    return (1);
}

sub getLoginFormHtml {

    my ($target) = @_;

    my $targetHtml = "";
    if (!empty($target)) {
	$targetHtml = "<input type=hidden name=target value='" . $target . "'></input>";
    }

    my $html_content = <<EOF;
<!doctype html>
<html lang="en">

<head>
<link href="//netdna.bootstrapcdn.com/bootstrap/3.1.0/css/bootstrap.min.css" rel="stylesheet" id="bootstrap-css">
<script src="//netdna.bootstrapcdn.com/bootstrap/3.1.0/js/bootstrap.min.js"></script>
<script src="//code.jquery.com/jquery-1.11.1.min.js"></script>
</head>
<body>
    <div class="container">    
        <div id="loginbox" style="margin-top:50px;" class="mainbox col-md-6 col-md-offset-3 col-sm-8 col-sm-offset-2">                    
            <div class="panel panel-primary" >
                    <div class="panel-heading">
                        <div class="panel-title">SSO Sign In</div>
                    </div>     

                    <div style="padding-top:30px" class="panel-body" >

                        <div style="display:none" id="login-alert" class="alert alert-danger col-sm-12"></div>
                            
                        <form id="loginform" method="post" action="/sso" class="form-horizontal" role="form">
                                    
                            <div style="margin-bottom: 25px" class="input-group">
                                        <span class="input-group-addon"><i class="glyphicon glyphicon-user"></i></span>
                                        <input id="login-username" type="text" class="form-control" name="username" value="" placeholder="Enter your username">
                                    </div>
                                
                            <div style="margin-bottom: 25px" class="input-group">
                                        <span class="input-group-addon"><i class="glyphicon glyphicon-lock"></i></span>
                                        <input id="login-password" type="password" class="form-control" name="password" placeholder="Enter your password">
                                    </div>
	                    ${targetHtml}
			    <div class="input-group">
                                <div style="margin-top:10px" class="form-group">
                                    <!-- Button -->

                                    <div class="col-sm-12 controls">
                                      <input type="submit" id="btn-login" class="btn btn-success" value="Login"></input>
                                    </div>
                                </div>
                            </div>
                            </form>
                         </div>
                    </div>                
         </div> 
    </div>
</body>
</html>
EOF
    
    return($html_content);
}

  #Got next 2 from here (orig called urlize and un_urlize): http://code.activestate.com/recipes/577450-perl-url-encode-and-decode/
  sub uri_encode {
      my ($rv) = @_;
      $rv =~ s/([^A-Za-z0-9])/sprintf("%%%2.2X", ord($1))/ge;
      return $rv;
   }

  sub uri_decode {
      my ($rv) = @_;
      $rv =~ s/\+/ /g;
      $rv =~ s/%(..)/pack("c",hex($1))/ge;
      return $rv;
   }

  sub logit {
	
     my ($msg) = @_;

     open F, ">>/tmp/AKSlog.txt";
     print F "PROC $$ : $msg";
     close(F);
}

sub read_config {

    my ($config_file_loc) = @_;

    my $config = {};

    open CF, "$config_file_loc" || die "Error opening config file: $!\n";
    while (my $curline = <CF>) {
	chomp $curline;
	next if (empty($curline)); #filter empty lines
	next if ($curline =~ /^\#/); #filter comment lines
	if ($curline =~ m/^(.+?)\s*\=\s*(.+)$/) {
	    my $varname = $1;
	    my $val = $2;
	    $config->{uc($varname)} = $val;
	}
    }
    close(CF);
    return($config);
}



#Or could use:
#      use Cookie::Baker;
#      my $cookies_hashref = crush_cookie($r->headers_in()->{Cookie});
  sub parseCookies {

      my ($cookies) = @_;

      if (empty($cookies)) { $cookies = ""; }

      my $cookiesHash = {};
      my @cookiesSplit = split /\s*;\s*/, $cookies;
      foreach my $curCookie (@cookiesSplit) {
	  if ($curCookie =~ m/^(.+)=(.+)$/i) {
	      my $cname = $1;
	      my $cvalue = $2;
	      $cname = rem_ws($cname);
	      $cvalue = rem_ws($cvalue);
	      $cookiesHash->{$cname} = $cvalue;
	  }
      }
      return($cookiesHash);
  }

  sub rem_ws {
      my ($inVal) = @_;

      if (!defined($inVal)) { return(""); }
      $inVal =~ s/^\s+//;
      $inVal =~ s/\s+$//;
      return($inVal);
}

  sub empty {
      my ($inVal) = @_;

      if (!defined($inVal)) { return(1); }
      if ($inVal =~ m/^\s*$/) { return(1); }
      return(0);
}
  
1;
