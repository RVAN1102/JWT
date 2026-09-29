$(document).ready(function() {
    const token = localStorage.getItem("jwt_token");

    if (window.location.pathname.includes("/user/profile")) {
        if (!token) {
            window.location.href = "/login";
            return;
        }

        $.ajax({
            type: "GET",
            url: "/users/me",
            headers: {
                "Authorization": "Bearer " + token
            },
            success: function(user) {
                $("#userFullName").text(user.fullName);
                $("#userEmail").text(user.email);
                $("#userId").text(user.id);
                $("#userAvatar").attr("src", user.images || "https://images.unsplash.com/photo-1535713875002-d1d0cf377fde?auto=format&fit=crop&w=200&h=200&q=80");
            },
            error: function() {
                localStorage.removeItem("jwt_token");
                window.location.href = "/login";
            }
        });
    }

    $("#logoutBtn").on("click", function() {
        localStorage.removeItem("jwt_token");
        window.location.href = "/login";
    });

    $("#loginForm").on("submit", function(e) {
        e.preventDefault();
        const email = $("#loginEmail").val().trim();
        const password = $("#loginPassword").val();
        const alertBox = $("#authAlert");

        alertBox.hide().text("");

        $.ajax({
            type: "POST",
            url: "/auth/login",
            contentType: "application/json",
            data: JSON.stringify({ email: email, password: password }),
            success: function(response) {
                if (response && response.token) {
                    localStorage.setItem("jwt_token", response.token);
                    window.location.href = "/user/profile";
                }
            },
            error: function(xhr) {
                let msg = "Tên tài khoản hoặc mật khẩu không đúng";
                if (xhr.responseJSON && xhr.responseJSON.detail) {
                    msg = xhr.responseJSON.detail;
                } else if (xhr.responseJSON && xhr.responseJSON.description) {
                    msg = xhr.responseJSON.description;
                }
                alertBox.removeClass("alert-success").addClass("alert-danger").text(msg).show();
            }
        });
    });

    $("#signupForm").on("submit", function(e) {
        e.preventDefault();
        const fullName = $("#signupName").val().trim();
        const email = $("#signupEmail").val().trim();
        const password = $("#signupPassword").val();
        const alertBox = $("#authAlert");

        alertBox.hide().text("");

        $.ajax({
            type: "POST",
            url: "/auth/signup",
            contentType: "application/json",
            data: JSON.stringify({ fullName: fullName, email: email, password: password }),
            success: function() {
                $("#loginEmail").val(email);
                $("#loginPassword").val(password);
                const loginTab = document.getElementById("login-tab");
                if (loginTab) {
                    loginTab.click();
                }
                alertBox.removeClass("alert-danger").addClass("alert-success").text("Đăng ký tài khoản thành công. Vui lòng đăng nhập.").show();
            },
            error: function(xhr) {
                let msg = "Đăng ký không thành công";
                if (xhr.responseJSON && xhr.responseJSON.errors) {
                    msg = Object.values(xhr.responseJSON.errors).join(", ");
                } else if (xhr.responseJSON && xhr.responseJSON.detail) {
                    msg = xhr.responseJSON.detail;
                } else if (xhr.responseJSON && xhr.responseJSON.description) {
                    msg = xhr.responseJSON.description;
                }
                alertBox.removeClass("alert-success").addClass("alert-danger").text(msg).show();
            }
        });
    });
});
