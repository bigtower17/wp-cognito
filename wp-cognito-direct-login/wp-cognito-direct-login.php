<?php
/**
 * Plugin Name: AWS Cognito Direct Login
 * Description: Direct login with Cognito (without Hosted UI) - Customisable style
 * Version: 1.0.0
 * Author: @bigtower17
 */

if (!defined('ABSPATH')) exit;

class WP_Cognito_Direct_Login {

    private $option_name = 'wp_cognito_direct_settings';

    public function __construct() {
        // Replace WordPress login form completely
        add_action('login_init', array($this, 'disable_default_login'));
        add_action('login_enqueue_scripts', array($this, 'enqueue_login_assets'));
        add_action('login_header', array($this, 'custom_login_page'));
        add_filter('login_message', array($this, 'suppress_default_messages'));

        // AJAX for direct login
        add_action('wp_ajax_nopriv_cognito_direct_login', array($this, 'handle_direct_login'));

        // Admin settings
        add_action('admin_menu', array($this, 'add_admin_menu'));
        add_action('admin_init', array($this, 'register_settings'));

        // Role-based redirect
        add_filter('login_redirect', array($this, 'role_based_redirect'), 10, 3);

        // Redirect logout to home instead of wp-login.php
        add_action('wp_logout', array($this, 'logout_redirect'));
        add_filter('logout_redirect', array($this, 'logout_redirect_url'), 10, 3);

        // Redirect from "My account" to custom login for non-logged users
        add_action('template_redirect', array($this, 'redirect_myaccount_to_login'));
        add_filter('woocommerce_get_myaccount_page_permalink', array($this, 'filter_myaccount_url'));
    }

    public function logout_redirect() {
        // Clean Cognito session if needed
        wp_redirect(home_url());
        exit;
    }

    public function logout_redirect_url($redirect_to, $requested_redirect_to, $user) {
        // Force redirect to home after logout
        return home_url();
    }

    public function disable_default_login() {
        // Hide default form
        if (isset($_GET['action']) && $_GET['action'] === 'logout') {
            return;
        }
    }

    public function suppress_default_messages($message) {
        // Remove default WordPress messages
        return '';
    }

    public function enqueue_login_assets() {
        ?>
        <style>
            /* Complete reset of WordPress login */
            body.login {
                background: #111827 !important;
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                display: flex !important;
                min-height: 100vh;
                align-items: center;
                justify-content: center;
                margin: 0;
                padding: 0;
            }

            body.login #login {
                display: none !important; /* Hide WordPress form completely */
            }

            #cognito-login-container {
                display: flex;
                width: 100%;
                min-height: 100vh;
                margin: 0;
                padding: 0;
            }

            /* Left side - Logo/Branding */
            .cognito-left-side {
                flex: 1;
                background: #1f2937;
                border-right: 1px solid #374151;
                display: flex;
                flex-direction: column;
                justify-content: center;
                align-items: center;
                padding: 3rem;
            }

            .cognito-logo-wrapper {
                max-width: 400px;
                text-align: center;
            }

            .cognito-logo-wrapper img {
                width: 100%;
                max-width: 320px;
                height: auto;
                object-fit: contain;
                margin-bottom: 2rem;
            }

            .cognito-brand-text {
                color: #ffffff;
                font-size: 2rem;
                font-weight: 700;
                margin: 0 0 0.5rem 0;
            }

            .cognito-brand-tagline {
                color: #9ca3af;
                font-size: 1.125rem;
                margin: 0;
            }

            /* Right side - Login form */
            .cognito-right-side {
                flex: 1;
                background: #111827;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 2rem;
            }

            .cognito-card {
                width: 100%;
                max-width: 450px;
                background: #1f2937 !important;
                background-color: #1f2937 !important;
                border: 1px solid #374151;
                border-radius: 0.5rem;
                box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.3);
                padding: 2rem 2.5rem 2.5rem 2.5rem;
            }

            .cognito-logo {
                text-align: center;
                margin-bottom: 1rem;
                display: none; /* Hide logo in form, now it's on the left */
            }

            .cognito-logo img {
                height: 60px;
                width: auto;
                object-fit: contain;
            }

            /* Mobile responsive */
            @media (max-width: 1024px) {
                #cognito-login-container {
                    flex-direction: column;
                }

                .cognito-left-side {
                    display: none; /* Hide logo side on mobile */
                }

                .cognito-right-side {
                    min-height: 100vh;
                }

                .cognito-logo {
                    display: block; /* Show logo in form on mobile */
                }
            }

            .cognito-title {
                color: #ffffff;
                font-size: 1.5rem;
                font-weight: 700;
                text-align: center;
                margin-top: 0.75rem;
                margin-bottom: 0.5rem;
            }

            .cognito-description {
                color: #9ca3af;
                font-size: 0.875rem;
                text-align: center;
                margin-bottom: 1.5rem;
            }

            .cognito-form-group {
                margin-bottom: 1.25rem;
            }

            .cognito-label {
                display: block;
                color: #d1d5db;
                font-size: 0.875rem;
                font-weight: 500;
                margin-bottom: 0.5rem;
            }

            .cognito-input-wrapper {
                position: relative;
            }

            .cognito-input-icon {
                position: absolute;
                left: 1rem;
                top: 14px;
                color: #6b7280;
                width: 18px;
                height: 18px;
                pointer-events: none;
                display: flex;
                align-items: center;
            }

            .cognito-input {
                width: 100% !important;
                background: #374151 !important;
                background-color: #374151 !important;
                border: 1px solid #4b5563 !important;
                color: #ffffff !important;
                border-radius: 0.375rem !important;
                padding: 0.75rem 1rem 0.75rem 3rem !important;
                font-size: 0.95rem !important;
                height: 48px !important;
                box-sizing: border-box !important;
                transition: all 0.2s !important;
                -webkit-appearance: none !important;
                -moz-appearance: none !important;
                appearance: none !important;
                line-height: normal !important;
            }

            .cognito-input:focus {
                outline: none !important;
                border-color: #3b82f6 !important;
                box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1) !important;
                background: #374151 !important;
                background-color: #374151 !important;
            }

            .cognito-input::placeholder {
                color: #6b7280 !important;
            }

            /* Force override WordPress default input styles */
            input.cognito-input[type="email"],
            input.cognito-input[type="password"] {
                background: #374151 !important;
                background-color: #374151 !important;
                color: #ffffff !important;
            }

            /* Ensure card background stays dark */
            .cognito-card * {
                background-color: transparent;
            }

            .cognito-card form {
                background: transparent !important;
            }

            /* Remove white border around form */
            #cognito-direct-login-form {
                border: none !important;
                outline: none !important;
                box-shadow: none !important;
            }

            .cognito-button {
                width: 100%;
                background: #3b82f6;
                color: white;
                border: none;
                border-radius: 0.375rem;
                padding: 0.75rem 1.5rem;
                font-size: 1rem;
                font-weight: 600;
                height: 48px;
                cursor: pointer;
                display: flex;
                align-items: center;
                justify-content: center;
                transition: all 0.2s;
                margin-top: 1.5rem;
            }

            .cognito-button:hover:not(:disabled) {
                background: #2563eb;
                transform: translateY(-1px);
            }

            .cognito-button:disabled {
                opacity: 0.6;
                cursor: not-allowed;
            }

            .cognito-button svg {
                margin-right: 0.5rem;
                width: 20px;
                height: 20px;
            }

            .cognito-spinner {
                animation: spin 1s linear infinite;
            }

            @keyframes spin {
                from { transform: rotate(0deg); }
                to { transform: rotate(360deg); }
            }

            .cognito-error {
                background: #991b1b;
                border-left: 4px solid #ef4444;
                color: #fecaca;
                padding: 1rem;
                border-radius: 0.375rem;
                margin-bottom: 1.5rem;
                display: flex;
                align-items: start;
                gap: 0.75rem;
            }

            .cognito-error-icon {
                flex-shrink: 0;
                width: 20px;
                height: 20px;
                color: #fca5a5;
            }

            .cognito-error-content h4 {
                margin: 0 0 0.25rem 0;
                font-size: 0.875rem;
                font-weight: 600;
            }

            .cognito-error-content p {
                margin: 0;
                font-size: 0.75rem;
            }

            .cognito-footer {
                text-align: center;
                margin-top: 1.5rem;
                padding-bottom: 0.5rem;
            }

            .cognito-footer-text {
                color: #9ca3af;
                font-size: 0.75rem;
                margin: 0;
            }

            .cognito-footer-text.small {
                color: #6b7280;
                margin-top: 0.5rem;
                margin-bottom: 0;
            }

            .cognito-forgot-password {
                text-align: center;
                margin-top: 1rem;
            }

            .cognito-forgot-password a {
                color: #60a5fa;
                text-decoration: none;
                font-size: 0.875rem;
            }

            .cognito-forgot-password a:hover {
                color: #93c5fd;
                text-decoration: underline;
            }
        </style>

        <script>
        document.addEventListener('DOMContentLoaded', function() {
            const form = document.getElementById('cognito-direct-login-form');
            const emailInput = document.getElementById('cognito-email');
            const passwordInput = document.getElementById('cognito-password');
            const submitBtn = document.getElementById('cognito-submit-btn');
            const errorContainer = document.getElementById('cognito-error');

            if (form) {
                form.addEventListener('submit', async function(e) {
                    e.preventDefault();

                    const email = emailInput.value.trim();
                    const password = passwordInput.value;

                    if (!email || !password) {
                        showError('Email and password are required');
                        return;
                    }

                    submitBtn.disabled = true;
                    submitBtn.innerHTML = '<svg class="cognito-spinner" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg> Signing in...';
                    hideError();

                    try {
                        const response = await fetch('<?php echo admin_url('admin-ajax.php'); ?>', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/x-www-form-urlencoded',
                            },
                            body: new URLSearchParams({
                                action: 'cognito_direct_login',
                                email: email,
                                password: password,
                                nonce: '<?php echo wp_create_nonce('cognito_direct_login'); ?>'
                            })
                        });

                        const data = await response.json();

                        if (data.success) {
                            // Redirect to dashboard or home
                            window.location.href = data.data.redirect_url;
                        } else {
                            showError(data.data.message || 'Authentication error');
                            submitBtn.disabled = false;
                            submitBtn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg> Sign In';
                        }
                    } catch (error) {
                        showError('Connection error. Please try again.');
                        submitBtn.disabled = false;
                        submitBtn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg> Sign In';
                    }
                });
            }

            function showError(message) {
                errorContainer.innerHTML = `
                    <svg class="cognito-error-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <circle cx="12" cy="12" r="10"></circle>
                        <line x1="12" y1="8" x2="12" y2="12"></line>
                        <line x1="12" y1="16" x2="12.01" y2="16"></line>
                    </svg>
                    <div class="cognito-error-content">
                        <h4>Authentication Error</h4>
                        <p>${message}</p>
                    </div>
                `;
                errorContainer.style.display = 'flex';
            }

            function hideError() {
                errorContainer.style.display = 'none';
            }
        });
        </script>
        <?php
    }

    public function custom_login_page() {
        $options = get_option($this->option_name);
        $logo_url = !empty($options['logo_url']) ? $options['logo_url'] : plugins_url('assets/logo.png', __FILE__);

        ?>
        <div id="cognito-login-container">
            <!-- Left side - Logo/Branding -->
            <div class="cognito-left-side">
                <div class="cognito-logo-wrapper">
                    <img src="<?php echo esc_url($logo_url); ?>" alt="Monetito Logo">
                </div>
            </div>

            <!-- Right side - Login Form -->
            <div class="cognito-right-side">
                <div class="cognito-card">
                    <div class="cognito-logo">
                        <img src="<?php echo esc_url($logo_url); ?>" alt="Logo">
                    </div>

                    <h1 class="cognito-title">E-commerce Access</h1>
                    <p class="cognito-description">Enter your credentials to continue</p>

                <div id="cognito-error" class="cognito-error" style="display: none;"></div>

                <form id="cognito-direct-login-form" method="post">
                    <div class="cognito-form-group">
                        <label for="cognito-email" class="cognito-label">Email</label>
                        <div class="cognito-input-wrapper">
                            <svg class="cognito-input-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"></path>
                                <polyline points="22,6 12,13 2,6"></polyline>
                            </svg>
                            <input
                                type="email"
                                id="cognito-email"
                                class="cognito-input"
                                placeholder="enter your email"
                                required
                                autocomplete="email"
                            >
                        </div>
                    </div>

                    <div class="cognito-form-group">
                        <label for="cognito-password" class="cognito-label">Password</label>
                        <div class="cognito-input-wrapper">
                            <svg class="cognito-input-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                                <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
                            </svg>
                            <input
                                type="password"
                                id="cognito-password"
                                class="cognito-input"
                                placeholder="enter your password"
                                required
                                autocomplete="current-password"
                            >
                        </div>
                    </div>

                    <button type="submit" id="cognito-submit-btn" class="cognito-button">
                        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                            <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
                        </svg>
                        Sign In
                    </button>
                </form>

                    <div class="cognito-footer">
                        <p class="cognito-footer-text">Secure access via AWS Cognito</p>
                        <p class="cognito-footer-text small">Authorized personnel only</p>
                    </div>
                </div>
            </div>
        </div>
        <?php

        // Terminate output to avoid showing the rest of the login page
        echo '</body></html>';
        exit;
    }

    public function handle_direct_login() {
        check_ajax_referer('cognito_direct_login', 'nonce');

        $email = sanitize_email($_POST['email']);
        $password = $_POST['password'];

        if (empty($email) || empty($password)) {
            wp_send_json_error(array('message' => 'Email and password are required'));
        }

        $options = get_option($this->option_name);

        if (empty($options['region']) || empty($options['client_id']) || empty($options['client_secret'])) {
            wp_send_json_error(array('message' => 'Cognito configuration is incomplete'));
        }

        // Authenticate with Cognito using InitiateAuth
        $result = $this->authenticate_with_cognito($email, $password, $options);

        if (is_wp_error($result)) {
            wp_send_json_error(array('message' => $result->get_error_message()));
        }

        // Get user info from token
        $user_info = $this->decode_id_token($result['IdToken']);
        $cognito_groups = isset($user_info['cognito:groups']) ? $user_info['cognito:groups'] : array();

        // Create or update WordPress user
        $user_id = $this->get_or_create_user($user_info, $cognito_groups);

        if (is_wp_error($user_id)) {
            wp_send_json_error(array('message' => $user_id->get_error_message()));
        }

        // WordPress login
        wp_set_auth_cookie($user_id, true);

        // Determine redirect based on role
        $user = new WP_User($user_id);
        $redirect_url = user_can($user, 'edit_posts') ? admin_url() : home_url();

        wp_send_json_success(array('redirect_url' => $redirect_url));
    }

    private function authenticate_with_cognito($email, $password, $options) {
        // Use AWS SDK or direct API call
        $region = $options['region'];
        $client_id = $options['client_id'];
        $client_secret = $options['client_secret'];

        // Calculate SECRET_HASH
        $secret_hash = base64_encode(hash_hmac('sha256', $email . $client_id, $client_secret, true));

        $data = array(
            'AuthFlow' => 'USER_PASSWORD_AUTH',
            'ClientId' => $client_id,
            'AuthParameters' => array(
                'USERNAME' => $email,
                'PASSWORD' => $password,
                'SECRET_HASH' => $secret_hash
            )
        );

        $response = wp_remote_post("https://cognito-idp.{$region}.amazonaws.com/", array(
            'headers' => array(
                'Content-Type' => 'application/x-amz-json-1.1',
                'X-Amz-Target' => 'AWSCognitoIdentityProviderService.InitiateAuth'
            ),
            'body' => json_encode($data),
            'timeout' => 30
        ));

        if (is_wp_error($response)) {
            return $response;
        }

        $body = json_decode(wp_remote_retrieve_body($response), true);

        if (isset($body['__type'])) {
            $error_message = isset($body['message']) ? $body['message'] : 'Authentication error';
            return new WP_Error('cognito_auth_error', $error_message);
        }

        if (!isset($body['AuthenticationResult'])) {
            return new WP_Error('cognito_auth_error', 'Invalid Cognito response');
        }

        return $body['AuthenticationResult'];
    }

    private function decode_id_token($id_token) {
        $parts = explode('.', $id_token);
        if (count($parts) !== 3) {
            return array();
        }

        $payload = base64_decode(str_pad(strtr($parts[1], '-_', '+/'), strlen($parts[1]) % 4, '=', STR_PAD_RIGHT));
        return json_decode($payload, true);
    }

    private function get_or_create_user($user_info, $cognito_groups = array()) {
        $email = isset($user_info['email']) ? sanitize_email($user_info['email']) : '';

        if (empty($email)) {
            return new WP_Error('no_email', 'Email not provided by Cognito');
        }

        $user = get_user_by('email', $email);

        if ($user) {
            $this->update_user_role($user->ID, $cognito_groups);
            update_user_meta($user->ID, 'cognito_sub', $user_info['sub']);
            update_user_meta($user->ID, 'cognito_groups', $cognito_groups);
            return $user->ID;
        }

        // Create new user
        $username = isset($user_info['cognito:username']) ? sanitize_user($user_info['cognito:username']) : sanitize_user($email);

        $base_username = $username;
        $counter = 1;
        while (username_exists($username)) {
            $username = $base_username . $counter;
            $counter++;
        }

        $role = $this->map_cognito_group_to_role($cognito_groups);

        $user_data = array(
            'user_login' => $username,
            'user_email' => $email,
            'user_pass' => wp_generate_password(20, true, true),
            'first_name' => isset($user_info['given_name']) ? $user_info['given_name'] : '',
            'last_name' => isset($user_info['family_name']) ? $user_info['family_name'] : '',
            'display_name' => isset($user_info['name']) ? $user_info['name'] : $username,
            'role' => $role
        );

        $user_id = wp_insert_user($user_data);

        if (!is_wp_error($user_id)) {
            update_user_meta($user_id, 'cognito_sub', $user_info['sub']);
            update_user_meta($user_id, 'cognito_groups', $cognito_groups);
        }

        return $user_id;
    }

    private function map_cognito_group_to_role($cognito_groups) {
        $options = get_option($this->option_name);
        $role_mapping = isset($options['role_mapping']) ? $options['role_mapping'] : '';

        $mappings = array();
        $lines = explode("\n", $role_mapping);
        foreach ($lines as $line) {
            $line = trim($line);
            if (empty($line)) continue;

            $parts = explode(':', $line);
            if (count($parts) === 2) {
                $mappings[trim($parts[0])] = trim($parts[1]);
            }
        }

        foreach ($cognito_groups as $group) {
            if (isset($mappings[$group])) {
                return $mappings[$group];
            }
        }

        return 'subscriber';
    }

    private function update_user_role($user_id, $cognito_groups) {
        $new_role = $this->map_cognito_group_to_role($cognito_groups);
        $user = new WP_User($user_id);
        $user->set_role($new_role);
        update_user_meta($user_id, 'cognito_groups', $cognito_groups);
    }

    public function role_based_redirect($redirect_to, $requested_redirect_to, $user) {
        if (!isset($user->ID)) {
            return $redirect_to;
        }

        if (user_can($user, 'edit_posts')) {
            return admin_url();
        }

        return home_url();
    }

    // Admin Settings
    public function add_admin_menu() {
        add_options_page(
            'Cognito Direct Login',
            'Cognito Login',
            'manage_options',
            'wp-cognito-direct-login',
            array($this, 'settings_page')
        );
    }

    public function register_settings() {
        register_setting($this->option_name, $this->option_name);

        add_settings_section('main', 'Cognito Configuration', null, 'wp-cognito-direct-login');

        $fields = array(
            'region' => 'AWS Region',
            'user_pool_id' => 'User Pool ID',
            'client_id' => 'Client ID',
            'client_secret' => 'Client Secret',
            'logo_url' => 'Logo URL',
            'role_mapping' => 'Role Mapping'
        );

        foreach ($fields as $key => $label) {
            add_settings_field($key, $label, array($this, 'field_callback'), 'wp-cognito-direct-login', 'main', array('key' => $key, 'type' => $key === 'role_mapping' ? 'textarea' : ($key === 'client_secret' ? 'password' : 'text')));
        }
    }

    public function field_callback($args) {
        $options = get_option($this->option_name);
        $value = isset($options[$args['key']]) ? $options[$args['key']] : '';

        if ($args['type'] === 'textarea') {
            echo '<textarea name="' . $this->option_name . '[' . $args['key'] . ']" rows="5" class="large-text">' . esc_textarea($value) . '</textarea>';
            echo '<p class="description">Format: cognito_group:wp_role (one per line)</p>';
        } else {
            echo '<input type="' . esc_attr($args['type']) . '" name="' . $this->option_name . '[' . $args['key'] . ']" value="' . esc_attr($value) . '" class="regular-text" />';
        }
    }

    public function settings_page() {
        ?>
        <div class="wrap">
            <h1>Cognito Direct Login</h1>
            <form method="post" action="options.php">
                <?php
                settings_fields($this->option_name);
                do_settings_sections('wp-cognito-direct-login');
                submit_button();
                ?>
            </form>
        </div>
        <?php
    }
}

new WP_Cognito_Direct_Login();
