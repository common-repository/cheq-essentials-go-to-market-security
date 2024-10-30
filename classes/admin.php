<?php

class CHEGTMS_Admin
{
    /**
     * Init ClickCease Plugin.
     */
    public function init_clickcease_field_setting()
    {
        // Add new admin menu options page for AP Setting.
        add_action('admin_menu', [$this, 'create_clickcease_plugin_options_page']);

        // Register ClickCease Plugin settings.
        add_action('admin_init', [$this, 'clickcease_admin_init'], 99);
    }

    /**
     * Admin init action with lowest execution priority
     */
    public function clickcease_admin_init()
    {
        // Admin Scripts.
        add_action('admin_enqueue_scripts', [$this, 'admin_enqueue_scripts']);
    }

    /**
     * Create the ClickCease Plugin options page
     */
    public function create_clickcease_plugin_options_page()
    {
        $option_name = CHEQ_ESSENTIAL ? 'CHEQ Essential' : 'ClickCease Plugin';

        add_menu_page(
            $option_name,
            $option_name,
            'manage_options',
            CC_PLUGIN_PAGE,
            [$this, 'clickcease_plugin_options_page_html'],
            'dashicons-menu',
            150
        );
    }

    /**
     * Create the AP Settings options page HTML
     */
    public function clickcease_plugin_options_page_html()
    {
        // check user capabilities.
        if (current_user_can('manage_options')) {
            echo '<div class="wrap"><div id="wp-cc-plugin"></div></div>';
        }
    }

    /**
     * Load Admin scripts
     */
    public function admin_enqueue_scripts($hook)
    {
        $screen = get_current_screen();

        // no need to inject admin page to any admin pages only to our page
        if (strpos($screen->id, CC_PLUGIN_PAGE) !== false) {
            wp_enqueue_script('wp-cc', CHEGTMS_PLUGIN_URL . '/build/static/js/main.29a24134.js', ['jquery', 'wp-element'], wp_rand(), true);
            wp_enqueue_style('clickcease-setting-style', CHEGTMS_PLUGIN_URL . '/build/static/css/main.34a27de5.css', [], CHEGTMS_VERSION);
            wp_localize_script('wp-cc', 'ajax_obj', [
                'nonce' => wp_create_nonce('wp_rest'),
                "ajax_url" => admin_url('admin-ajax.php'),
                "cheq_essential" => CHEQ_ESSENTIAL
            ]);
        }
    }
}
