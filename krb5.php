<?php

/**
 * Kerberos password driver
 *
 * @version 0.9
 * @author Colin King
 *
 * Copyright (C) 2016, Colin King
 * Based on the PAM driver by Aleksander Machniak
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see http://www.gnu.org/licenses/.
 */

class rcube_krb5_password
{
    function save($currpass, $newpass)
    {
        $user  = $_SESSION['username'];
        $error = '';

        $realm = rcmail::get_instance()->config->get('krb5_realm','');
        $princ = $user . '@' . $realm;

        if (extension_loaded('krb5')) {
            try {
                KRB5CCache::changePassword($princ, $currpass, $newpass);
                return PASSWORD_SUCCESS;
            }
            catch (Exception $e) {
                $error = $e->getMessage();
                rcube::raise_error(array(
                    'code' => 600,
                    'type' => 'php',
                    'file' => __FILE__, 'line' => __LINE__,
                    'message' => "Password plugin: Kerberos authentication failed for principal $princ: $error"
                    ), true, false);
            }
        }
        else {
            rcube::raise_error(array(
                'code' => 600,
                'type' => 'php',
                'file' => __FILE__, 'line' => __LINE__,
                'message' => "Password plugin: PECL-krb5 module not loaded"
                ), true, false);
        }

        return PASSWORD_ERROR;
    }
}
