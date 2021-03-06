<!-- auth.html -- retrieves and displays basic user account information -->
<!DOCTYPE html>
<html>
<body>
<h1>auth.html</h1>
<p id="cid">{{cid}}</p>
<p id="access_token">Access Token:<br /></p>
<p id="token_info">Token Information:<br /></p>
<p id="validity">Validity Check:<br /></p>
<p id="profile_info">Profile Info:<br /></p>
<p id="profile_result">Result:<br /></p>
<script>

// Provided

function print_to_page(pname, msg) {
    document.getElementById(pname).innerHTML += msg;
    document.getElementById(pname).innerHTML += "<br />";
}

var Client_ID = document.getElementById("cid").innerHTML;

// First, parse the query string
var params = {}, queryString = location.hash.substring(1),
 regex = /([^&=]+)=([^&]*)/g, m;
while (m = regex.exec(queryString)) {
  params[decodeURIComponent(m[1])] = decodeURIComponent(m[2]);
}

if (typeof(params["access_token"]) != 'undefined') {
    print_to_page("access_token", params["access_token"]);
} else {
    print_to_page("access_token", "There is no access token");
}

validity_failed_msg = "Validity check failed!";
validity_succeeded_msg = "Access Token is valid!";

var req = new XMLHttpRequest();

// ---- YOUR CODE BEGIN ----
var clientID = "{{cid}}";

function initPage(){
	$.get("https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=" + params["access_token"])
		.done(function(response){
			if(response.audience == clientID){
				print_to_page("validity", validity_succeeded_msg);
				getPeopleInfo();
			}else{
				print_to_page("validity", validity_failed_msg);
			}
		})
		.fail(function(response){
			print_to_page("validity", validity_failed_msg);
		});
}

// Load jQuery library and start page processing
var script = document.createElement("script");
script.src="http://code.jquery.com/jquery-1.11.3.min.js";
script.addEventListener("load", initPage);
document.body.appendChild(script);

// ---- YOUR CODE END ----

// Provided

function getPeopleInfo() {
    req.open('GET', 'https://www.googleapis.com/plus/v1/people/me?access_token=' + params["access_token"], true)
    req.onreadystatechange = function (e) {
        if (req.readyState == 4) {
	    print_to_page("profile_info", req.responseText);
	    if(req.status == 200){
	        print_to_page("profile_result", "Profile is retrieved successfully!");
	    } else {
	        print_to_page("profile_result", "Failed to retrieve Profile!");
	    }
	} 
    };
    req.send(null);
}

</script>
</body>
</html>

