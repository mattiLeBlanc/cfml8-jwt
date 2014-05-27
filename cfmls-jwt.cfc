/*
    JWT Coldfusion Script component, loosly based on PHP version @ https://github.com/firebase/php-jwt

    Description:        This component exposes a encode and decode function which let's you read a JSON Web Token or create one
                        The component is specically written for Coldfusion 8 because of the platform I had to work on.
                        It will also work on newer coldfusions (havent tested it yet), where as CFML 10 finally added the HMac() function which would make
                        the CFHashMac redudant.

                        If you rewrite this component, please Fork it.

    Author:             Mattijs Spierings
    Date:               13/5/2014
    Version:            1.0
    License:            GPL V2

    Reference on JWT:   http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html

    To do:
        -add encryption options of header and payload to create JWE
        -if Coldfusion 10+ replace custom hashmac function for native (make sure reasult is the same)

    NOTE: Concerning getCurrentUtcTime function at the bottom: Not tested if getTime() from currentDate will result in epoch date in CFML9+.
          In version 8 it does. If newer version of CFML causes troube, use the utcDate variable and test if the epoch time is correct
 */


component jwt
{
    this.encoding   = "iso-8859-1";
    this.iss        = "";
    this.aud        = "";
    this.exp        = "";
    this.iat        = "";

    /**
     * the constructor, returning a jwt object
     * @param string iss        The 'iss' field is a standard JWT field that identifies the issuer of the JWT
     * @param string aud        The 'aud' field is a standard JWT field that identifies the target audience for the JWT.
     * @param numeric exp       The expiration time in seconds after the 'iat' (issued at time) field. This is a standard JWT field.
     * @param string encoding   The string encoding used in hsmac funcion. Not required, but default utf-8
     *
     * @return jwt object
     */
    public jwt function init( Required string iss, Required string aud, Required numeric exp, Required string encoding )
    {
        this.iss         = Arguments.iss;
        this.aud         = Arguments.aud;
        this.exp         = Arguments.exp;
        this.encoding    = Arguments.encoding;

        return this;

    }

    /**
     * encode function
     * @param any payload       the object to be encoded within the token
     * @param string key        the secret key to encoded the signature
     * @param algo string       the encoding algorith, standard HS256
     *
     * @return string JSON Web Token
     */
     public string function encode( Required any payload, Required string key, Required string algo )
     {
        //define our variables here
        var currentTime = getCurrentUtcTime();
        var header      = createObject("java", "java.util.LinkedHashMap").init(); // StructNew doesnt work because coldfusion orders the keys (does it also do this in newer versions?)
        var claims      = createObject("java", "java.util.LinkedHashMap").init(); // StructNew doesnt work because coldfusion orders the keys (does it also do this in newer versions?)
        var segments    = [];

        // creation of first segment of our JWT: the header
        //
        header[ "typ" ] = "JWT";
        header[ "alg" ] = Arguments.algo;
        // add header an json with base64 encoding to segment array
        //
        arrayAppend( segments, replace( toBase64( serializeJSON( header ) ), "=", "", "all" ) );

        // creation of the middle segment: the claims set
        //
        claims[ "iss" ]     = this.iss;
        claims[ "aud" ]     = this.aud;
        claims[ "iat" ]     = javaCast( "int", currentTime );
        claims[ "exp" ]     = javaCast( "int", ( currentTime + this.exp ) );
        claims[ "request" ] = Arguments.payload;

        // escape forward slashes in generated JSON
        //
        claimsJson          = replace(  serializeJSON( claims ), "/", "\/", "all" );
        // add header and json with base64 encoding (with padding REMOVED!) to segment array
        //
        arrayAppend( segments, replace( toBase64( claimsJson ), "=", "", "all" ) );

        // create the last segment: the signature
        //
        signingInput        = ArrayToList( segments, "." );
        signature           = sign( signingInput, Arguments.key, Arguments.algo );

        // add signature as last the element to our string
        //
        return ListAppend( signingInput, signature, ".");
     }

     /**
      * decode function
      * @param string jwt       the JSON Web token to be decodded
      * @param string key       the secret key necessary to verify the signature
      * @param boolean verify   if set to true, function will verify signature and return payload if signature matches
      *
      * @return any payload object
      */
     public any function decode( Required string jwt, Required string key, Required boolean verify )
     {
        try
        {
            local.parts              = listToArray( Arguments.jwt, "." );

            // assurre we have received 3 segments (head, body and  hMAC )
            //
            if ( ArrayLen( local.parts ) neq 3 )
            {
                throw type="Application" message="invalidSegmentCount";
            }

            local.head64             = local.parts[ 1 ];
            local.body64             = local.parts[ 2 ];
            local.crypto64           = local.parts[ 3 ];

            local.header             = DeserializeJson( urlsafeB64Decode( local.head64 ) );
            local.payload            = DeserializeJson( urlsafeB64Decode( local.body64 ) );
            local.signature          = urlsafeB64Decode( local.crypto64 );

            // Let's verify the sigature.
            // To do this we are going to construct a new signature of the header, payload and compare this to the one we received
            //
            if ( Arguments.verify )
            {

                if ( !StructKeyExists( local.header, "alg" ) )
                {
                    throw type="Application" message="noAlgor";
                }

                local.signinginput   = "#local.head64#.#local.body64#";
                local.testSignature  = sign( local.signinginput, Arguments.key, local.header.alg );

                // finally test the new signature with the received one
                //
                if ( urlsafeB64Decode( local.testSignature ) neq local.signature )
                {
                    throw type="Application" message="sigFailed";
                }
            }

            return local.payload;
        }
        catch( any message )
        {
            switch( cfcatch.message )
            {
                case "invalidSegmentCount":
                    writeOutput( "Wrong nubmber of segments" );
                break;
                case "noAlgor":
                    writeOutput( "No algorithm defined in header" );
                break;

                case "sigFailed":
                    writeOutput( "Signature verification failed" );
                break;

                default:
                    writeOutput( cfcatch.message );
                break;
            }

            // no return, abort request
            //
            abort;

        }

     }

     /**
      * Sign a string with a given key and algorithm
      * @param string msg       the content to be used to calculate the signature
      * @param string key       the secret message to secure the signature
      * @param string method    the signing algorithm. We only use hcmacSHA256 right because that is suggested in JWT draft
      *
      * @return string          hasmac signature
      */
     private string function sign( Required string msg, Required string key, Required string method )
     {

        var hashmac         = CFHashMac( Arguments.msg, Arguments.key, Arguments.method );


        // replace + and - characters and remove padding ( = )
        //
        local.hashmac        = replace( local.hashmac, "+", "-", "all");
        local.hashmac        = replace( local.hashmac, "/", "_", "all");
        local.hashmac        = replace( local.hashmac, "=", "", "all");

        return local.hashmac;
     }

     /**
      * UrlSafeBinary64 encoding function that will replace return the +/ characters and apply padding
      * @param string input     the base64 input to be decoded
      *
      * @return string          the decoded string value of the input
      */
     private string function urlsafeB64Decode( Required string input )
     {
        // return non websafe characters
        //
        Arguments.input      = replace( Arguments.input, "-", "+", "all")>
        Arguments.input      = replace( Arguments.input, "_", "/", "all")>

        local.remainder      = len( Arguments.input ) mod 4;

        // add padding to input string so that it is a valid base64 format
        //
        if ( local.remainder Gt 0 )
        {
            local.padlen     = 4 - local.remainder;
            Arguments.input  = Arguments.input & RepeatString( "=", local.padlen );
        }

        local.binaryValue    = binaryDecode( Arguments.input, "base64" );
        local.stringValue    = toString( local.binaryValue );

        local.stringValue;
     }

     /**
      * Generate a keyed hashvalue using the HMAC method
      * @param string msg       the content to be hashmaced
      * @param string key       the secret key to sign the hash
      * @mparam string mehhod   the encoding method
      *
      * @return string          base64 hashmac value of msg
      */
     private string function CFHashMac( Required string msg, Required string key, Required string method )
     {§

        switch( Arguments.method)
        {
            case "HS256":
                local.algor  = "HmacSHA256";
            break;

            default
                local.algor  = "HmacSHA256";
            break;
        }

       local.key             = createObject("java", "javax.crypto.spec.SecretKeySpec").init(
            Arguments.key.getBytes( this.encoding ), local.algor
        );

       local.mac             = createObject("java", "javax.crypto.Mac" ).getInstance( local.algor );
       local.mac.init( local.key );

       return toBase64(
            local.mac.doFinal(
                Arguments.msg.getBytes( this.encoding )
            )
       );
     }

    /**
     *  Return current UTC time in seconds
     *
     * @return time in seconds from epoch
     * NOTE: Not tested if getTime from currentDate will result in epoch date in CFML9+. In version 8 it does. If newer version of CFML causes troube, use the utcDate variable and test if the epoch time is correct
     */
     private numeric function getCurrentUtcTime()
     {
        local.currentDate = Now();
        //local.utcDate = dateConvert( "local2utc", local.currentDate );
        //return round( local.utcDate.getTime() / 1000 );
        return round( local.currentDate.getTime() / 1000 );
     }




}