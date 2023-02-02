<?php
/**
 * Default settings for the authclientcert plugin
 *
 * @author Pawel Jasinski <pawel.jasinski@gmail.com>
 */

$conf['http_header_name'] = 'HTTP_X_SSL_CLIENTCERT_BASE64';
$conf['name_var'] = '2.16.840.1.113730.3.1.3';
$conf['fullname_var'] = 'subject, CN';
$conf['email_var'] = 'extensions, subjectAltName, email';
$conf['group'] = 'smartcarduser';
$conf['debug'] = 0;

