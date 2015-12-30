<?php
// must be run within Dokuwiki
if(!defined('DOKU_INC')) die();

/**
* Chained authentication backend
*
* @license    MIT https://opensource.org/licenses/MIT
* @author     Tomas Kadlec <tomas@tomaskadlec.net>
* 
* Idea based on:
* * "Chained authentication backend" by Grant Gardner <grant@lastweekend.com.au> see https://www.dokuwiki.org/auth:ggauth
* * "Authchained plugin" by  https://www.dokuwiki.org/plugin:authchained
*
*/
class auth_plugin_authchained extends DokuWiki_Auth_Plugin {

    /**
     * The chain - array of configured plugins
     * @var DokuWiki_Auth_Plugin[]
     */
    protected $plugins;

    /**
     * Currently used plugin
     * @var DokuWiki_Auth_Plugin
     */
    protected $currentPlugin;

    /**
     * Plugin used with usermanager
     * @var
     */
    protected $usermanagerPlugin;

    /**
     * Builds the chain, initializes current and usermanager plugins.
     */
    public function __construct() {
        parent::__construct();

        // initialize auth plugin for the current user if set
        $currentPluginName = $this->getCurrentPluginName();
        if (!empty($currentPluginName)) {
            $this->currentPlugin = plugin_load('auth', $currentPluginName);
            if (empty($this->currentPlugin) || !$this->currentPlugin->success) {
                $this->msg(-1, 'plugin_not_initialized', array(':plugin:' => $currentPluginName));
                $this->success = false;
            }
        }

        // initialize the chain
        $this->plugins = array();
        $plugins = $this->getConf('authtypes');
        if (!empty($plugins)) {
            $usermanagerPlugin = $this->getConf('usermanager_authtype');
            foreach (explode(':', $plugins) as $pluginName) {
                /** @var DokuWiki_Auth_Plugin $plugin */
                $plugin = plugin_load('auth', $pluginName);
                if (empty($plugin) || !$plugin->success) {
                    $this->msg(-1, 'plugin_not_initialized', array(':plugin:' => $pluginName));
                    continue;
                }
                // add the plugin to the chain
                $this->plugins[] = $plugin;
                // set chain capabilities
                foreach (array('external', 'getGroups') as $capability)
                    if ($plugin->canDo($capability))
                        $this->cando[$capability] = true;
                // set usermanager plugin capabilities
                if (!empty($usermanagerPlugin) && $pluginName == $usermanagerPlugin) {
                    $this->usermanagerPlugin = $plugin;
                    foreach($this->cando as $key => &$value)
                        $value = $value || $plugin->canDo($key);
                }
            }
        }
        if (empty($this->plugins))
            $this->success = false;
    }

    /** @inheritdoc */
    public function canDo($cap)
    {
        global $ACT;
        // It is important to know that auth_setup call canDo('external'). In such case the
        // $this->currentPlugin must be used. If it is not used and user is authenticated
        // via trustExternal() user is logged off!
        $callee = debug_backtrace(!DEBUG_BACKTRACE_PROVIDE_OBJECT, 2);
        if ($ACT == "admin"
            && $callee[1]['function'] != 'auth_setup'
            && (empty($_REQUEST['page']) || $_REQUEST['page'] == "usermanager")
            && !empty($this->usermanagerPlugin)) {
            return $this->usermanagerPlugin->canDo($cap);
        // If this part is used, auth plain users does not have roles
        } else if (!empty($this->currentPlugin)) {
            return $this->currentPlugin->canDo($cap);
        }
        return parent::canDo($cap);
    }

    /**
     * @inheritdoc
     */
    public function logOff() {
        if (!empty($this->currentPlugin))
            $this->currentPlugin->logOff();
        $this->unsetCurrentPluginName();
    }

    /**
     * @inheritdoc
     */
    public function trustExternal($user, $pass, $sticky = false) {
        /** @var DokuWiki_Auth_Plugin $plugin */
        foreach ($this->plugins as $plugin) {
            if ($plugin->canDo('external')) {
                $result = $plugin->trustExternal($user, $pass, $sticky);
                if ($result === true) {
                    $this->setCurrentPluginName($plugin);
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * @inheritdoc
     */
    public function checkPass($user, $pass) {
        /** @var DokuWiki_Auth_Plugin $plugin */
        foreach ($this->plugins as $plugin) {
            $result = $plugin->checkPass($user, $pass);
            if ($result === true) {
                $this->setCurrentPluginName($plugin);
                return true;
            }
        }
        return false;
    }

    /**
     * @inheritdoc
     */
    public function getUserData($user) {
        global $ACT;
        // user data for the usermanager plugin
        if ($ACT == "admin" && $_REQUEST['page']=="usermanager") {
            /** @var DokuWiki_Auth_Plugin $plugin */
            foreach ($this->plugins as $plugin) {
                $userdata = $plugin->getUserData($user);
                if (!empty($userdata)) {
                    $userdata['plugin'] = $plugin->getPluginName();
                    if ($plugin != $this->usermanagerPlugin)
                        $userdata['modify'] = false;
                    return $userdata;
                }
            }
	    }
        // otherwise data about current user are requested
        else if (!empty($this->currentPlugin))
            return $this->currentPlugin->getUserData($user);

        // in any other case ...
        return false;
    }

    /** @inheritdoc */
    public function createUser($user, $pass, $name, $mail, $grps = null) {
        if (!$this->canDoUsermanagerPlugin('addUser'))
            return null;
        return $this->usermanagerPlugin->createUser($user, $pass, $name, $mail, $grps);
    }

    /** @inheritdoc */
    public function modifyUser($user, $changes) {
        if (!$this->canDoUsermanagerPlugin('UserMod'))
            return false;
        return $this->usermanagerPlugin->modifyUser($user, $changes);
    }

    /** @inheritdoc */
    public function deleteUsers($users) {
        if (!$this->canDoUsermanagerPlugin('delUser'))
            return 0;
        return $this->usermanagerPlugin->deleteUsers($users);
    }

    /** @inheritdoc */
    public function getUserCount($filter = array()) {
        if (!$this->canDoUsermanagerPlugin('getUserCount'))
            return 0;
        return $this->usermanagerPlugin->getUserCount($filter);
    }

    /** @inheritdoc */
    public function retrieveUsers($start = 0, $limit = -1, $filter = null) {
        if (!$this->canDoUsermanagerPlugin('getUsers'))
            return array();
        return $this->usermanagerPlugin->retrieveUsers($start, $limit, $filter);
    }

    /** @inheritdoc */
    public function addGroup($group) {
        if (!$this->canDoUsermanagerPlugin('addGroup'))
            return false;
        return $this->usermanagerPlugin->addGroup($group);
    }

    /** @inheritdoc */
    public function retrieveGroups($start = 0, $limit = 0) {
        $groups = array();
        foreach ($this->plugins as $plugin) {
            if ($plugin->canDo('getGroups'))
                $groups = array_unique(array_merge($groups, $plugin->retrieveGroups()));
            if (($start + $limit > 0) && count($groups) >= ($start + $limit))
                break;
        }
        return array_slice($groups, $start, ($limit !== 0 ? $limit : NULL));
    }

    /** @inheritdoc */
    public function isCaseSensitive() {
        if (!empty($this->currentPlugin))
            return $this->currentPlugin->isCaseSensitive();

        return parent::isCaseSensitive();
    }

    /** @inheritdoc */
    public function cleanUser($user) {
        global $ACT;

        // the usermanager plugin
        if ($ACT == "admin" && $_REQUEST['page']=="usermanager") {
            /** @var DokuWiki_Auth_Plugin $plugin */
            foreach ($this->plugins as $plugin) {
                $userdata = $plugin->getUserData($user);
                if (!empty($userdata)) {
                    return $plugin->cleanUser($user);
                }
            }
        }
        // current plugin
        else if (!empty($this->currentPlugin))
            return $this->currentPlugin->cleanUser($user);

        // in any other case ...
        return parent::cleanUser($user);
    }

    /** @inheritdoc */
    public function cleanGroup($group) {
        /** @var DokuWiki_Auth_Plugin $plugin */
        foreach ($this->plugins as $plugin) {
            if ($plugin->canDo('getGroups')) {
                if (in_array($group, $plugin->retrieveGroups()))
                    return $plugin->cleanGroup($group);
            }
        }
        return parent::cleanGroup($group);
    }

    /** @inheritdoc */
    public function useSessionCache($user) {
        if (!empty($this->currentPlugin))
            return $this->currentPlugin->useSessionCache($user);

        return parent::useSessionCache($user);
    }

    /**
     * Returns name of auth plugin currently in use.
     *
     * @return null|string
     */
    protected function getCurrentPluginName()
    {
        if (isset($_SESSION[DOKU_COOKIE][$this->getPluginName()]['current']))
            return $_SESSION[DOKU_COOKIE][$this->getPluginName()]['current'];
        else
            return null;
    }

    /**
     * Sets the name of the auth plugin currently in use.
     *
     * @param DokuWiki_Auth_Plugin $plugin
     */
    protected function setCurrentPluginName(DokuWiki_Auth_Plugin $plugin)
    {
        $_SESSION[DOKU_COOKIE][$this->getPluginName()]['current'] = $plugin->getPluginName();
    }

    /**
     * Unsets the name of the auth plugin currently in use
     */
    protected function unsetCurrentPluginName()
    {
        unset($_SESSION[DOKU_COOKIE][$this->getPluginName()]['current']);
    }

    /**
     * Outputs translated message with placeholders (e.g. :PlHo:) replaced.
     * @param $severity
     * @param $msg
     * @param array $replacements
     */
    protected function msg($severity, $msg, array $replacements = array())
    {
        msg(
            str_replace(array_keys($replacements), array_values($replacements), $this->getLang($msg)),
            $severity
        );
    }

    /**
     * Checks if usermanager auth plugin is configured. If it is not a message
     * is sent to the output.
     *
     * @return bool
     */
    protected function isUsermanagerPluginConfigured() {
        if (empty($this->usermanagerPlugin)) {
            $this->msg(-1, 'usermanager_plugin_not_configured');
            return false;
        }
        return true;
    }

    /**
     * Checks if usermanager has a requested capability. If not a message is
     * sent to the output. Includes isUserManagerPluginConfigured.
     *
     * @param $capability
     * @return bool
     */
    protected function canDoUsermanagerPlugin($capability) {
        if (!$this->isUsermanagerPluginConfigured())
            return false;
        if (!$this->usermanagerPlugin->canDo($capability)) {
            $this->msg(-1, 'usermanager_plugin_not_capable', array(
                ':plugin:' => $this->usermanagerPlugin->getPluginName(),
            ));
            return false;
        }
        return true;
    }

}