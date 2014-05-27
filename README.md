cfmls-jwt
=========



 JWT Coldfusion Script component, loosly based on PHP version @ https://github.com/firebase/php-jwt

    Description:        This component exposes a encode and decode function which let you decode a JSON Web Token or create one
                        The compenent is based on CFML8-JWT but rewritten in CF Sript.
                        IT HAS NOT BEEN TESTED YET!

                        It will also work on newer coldfusions (havent tested it yet), whereas CFML 10 finally added the HMac() function which would make
                        the CFHashMac redudant.

                        If you rewrite this component, please Fork it.

    Author:             Mattijs Spierings
    Date:               13/5/2014
    License:            GPL V2

    Reference on JWT:   http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html

    To do:
        add encryption options of header and payload to create JWE

    NOTE:
        If you are using another version than Coldfusion 8, please check my comments at the function getCurrentUtcTime concerning proper epoch time.
        I haven't been able to test this on other versions than CFML 8


    See example.cfm file for encoding and decoding