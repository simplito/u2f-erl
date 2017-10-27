var appId = "http://localhost:8080";

function post(request) {
    console.log("post", request);
    var result = $.post({url:"/", data: JSON.stringify(request), contentType:"application/json; charset=utf-8"});
    result.then(function(response) {
        console.log("response", response);
    });
    return result;
}

function register() {
    post({action: "registerRequest"})
    .then(function(response) {
        u2f.register(response.appId, response.registerRequests, response.registeredKeys, (r) => {
            if ( r.errorCode == 4 ) {
                $("#log").append("<p>already registered</p>");
                return;
            } else if ( r.errorCode !== undefined ) {
                $("#log").append("<p>error " + r.errorCode + "</p>");
                return;
            }
            post({action: "register", response: r})
            .then((r) => {
                $("#log").append("<p>successfully registered - <b>" + r.certificateSubject + "</b></p>");
            })
            .catch(() => {
                $("#log").append("<p>registration failed</p>");
            })
        })
    })
}

function sign() {
    post({action: "sign"})
    .then(function(response) {
        u2f.sign(response.appId, response.challenge, response.registeredKeys, (r) => {

            if (r.errorCode !== undefined ) {
                $("#log").append("<p>error " + r.errorCode + "</p>");
                return;
            }

            post({action: "authenticate", response: r})
            .then((r) => {
                $("#log").append("<p>successfully authenticated</p>");
            })
            .catch(() => {
                $("#log").append("<p>login failed</p>");
            })
        })
    })
}

function reset() {
    post({action: "reset"})
    .then(function(response) {
      $("#log").append("ok");
    })
}

$(function() {
    $("#register").on('click', register);
    $("#sign").on('click', sign);
    $("#reset").on('click', reset);
});
