<!---
    JWT Coldfusion 8 component, loosly based on PHP version @ https://github.com/firebase/php-jwt

    Description:        This component exposes a encode and decode function which let's you read a JSON Web Token or create one
                        The component is specically written for Coldfusion 8 because of the platform I had to work on.
                        It will also work on newer coldfusions (havent tested it yet), where as CFML 10 finally added the HMac() function which would make
                        the CFHashMac redudant.

                        If you rewrite this component, please Fork it.

    Author:             Mattijs Spierings
    Date:               12/5/2014
    Version:            1.0
    License:            GPL V2

    Reference on JWT:   http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html

    To do:
        add encryption options of header and payload to create JWE
 --->


<cfcomponent>


    <cfset Variables.encoding = "iso-8859-1">
    <cfset Variables.iss = "">
    <cfset Variables.aud = "">
    <cfset Variables.exp = "">
    <cfset Variables.iat = "">



    <!---
        Constructor
    --->
    <cffunction name="init" access="public" returntype="cfml-jwt">

        <cfargument name="iss"          type="string"    required="Yes" hint="The 'iss' field is a standard JWT field that identifies the issuer of the JWT.">
        <cfargument name="aud"          type="string"    required="Yes" hint="The 'aud' field is a standard JWT field that identifies the target audience for the JWT.">
        <cfargument name="exp"          type="numeric"   required="Yes" hint="The expiration time in seconds after the 'iat' (issued at time) field. This is a standard JWT field.">
        <cfargument name="encoding"     type="string"    required="No" default="UTF-8">

        <cfset this.iss         = Arguments.iss>
        <cfset this.aud         = Arguments.aud>
        <cfset this.exp         = Arguments.exp>
        <cfset this.encoding    = Arguments.encoding>

        <cfreturn this>

    </cffunction>

    <!---
        encode function
        returns JWT string
     --->
    <cffunction name="encode" access="public" returntype="String">
        <!--- ****************** Arguments ************************ --->
        <cfargument name="payload" type="any" required="true">
        <cfargument name="key" type="string" required="true">
        <cfargument name="algo" type="string" required="false" default="HS256">
        <!--- ****************** /Arguments *********************** --->

        <!--- define our variables here  --->
        <cfset var currentTime = getCurrentUtcTime()>
        <cfset var header = createObject("java", "java.util.LinkedHashMap").init() /> <!--- StructNew doesnt work because coldfusion 8 orders the keys --->
        <cfset var claims = createObject("java", "java.util.LinkedHashMap").init() /> <!--- StructNew doesnt work because coldfusion 8 orders the keys --->
        <cfset var segments = ArrayNew(1)>

        <!---
            creation of first segment of our JWT: the header
        --->
        <cfset header[ "typ" ] = "JWT">
        <cfset header[ "alg" ] = Arguments.algo>
        <!--- add header an json with base64 encoding to segment array --->
        <cfset arrayAppend( segments, replace( toBase64( serializeJSON( header ) ), "=", "", "all" ) )>

        <!---
            creation of the middle segment: the claims set
        --->
        <cfset claims[ "iss" ] = this.iss>
        <cfset claims[ "aud" ] = this.aud>
        <cfset claims[ "iat" ] = javaCast( "int", currentTime )>
        <cfset claims[ "exp" ] = javaCast( "int", ( currentTime + this.exp ) )>
        <cfset claims[ "request" ] = Arguments.payload>
        <!---
            escape forward slashes in generated JSON
        --->
        <cfset claimsJson = replace(  serializeJSON( claims ), "/", "\/", "all" )>
        <!--- add header and json with base64 encoding (with padding REMOVED!) to segment array --->
        <cfset arrayAppend( segments, replace( toBase64( claimsJson ), "=", "", "all" ) )>

        <!---
            create the last segment: the signature
        --->
        <cfset signingInput = ArrayToList( segments, "." )>
        <cfset signature = sign( signingInput, Arguments.key, Arguments.algo )>

        <!---
            add signature as last the element to our string
        --->
        <cfreturn ListAppend( signingInput, signature, ".")>

    </cffunction>

    <!---
        decode function
        returns the payload
     --->
    <cffunction name="decode" access="public">
        <!--- ****************** Arguments ************************ --->
        <cfargument name="jwt" type="string" required="true">
        <cfargument name="key" type="string" required="true">
        <cfargument name="verify" type="boolean" required="true" default="true">
        <!--- ****************** /Arguments *********************** --->

        <cftry>

            <cfset local.parts              = listToArray( Arguments.jwt, "." )>

            <!---
                assurre we have received 3 segments (head, body and  hMAC )
            --->
            <cfif ArrayLen( local.parts ) neq 3>
                <cfthrow type="Application" message="invalidSegmentCount">
            </cfif>

            <cfset local.head64             = local.parts[ 1 ]>
            <cfset local.body64             = local.parts[ 2 ]>
            <cfset local.crypto64           = local.parts[ 3 ]>

            <cfset local.header             = DeserializeJson( urlsafeB64Decode( local.head64 ) )>
            <cfset local.payload            = DeserializeJson( urlsafeB64Decode( local.body64 ) )>
            <cfset local.signature          = urlsafeB64Decode( local.crypto64 )>

            <!---
                Let's verify the sigature.
                To do this we are going to construct a new signature of the header, payload and compare this to the one we received
            --->
            <cfif Arguments.verify>

                <cfif !StructKeyExists( local.header, "alg" )>
                    <cfthrow type="Application" message="noAlgor">
                </cfif>

                <cfset local.signinginput   = "#local.head64#.#local.body64#">
                <cfset local.testSignature  = sign( local.signinginput, Arguments.key, local.header.alg )>

                <!--- finally test the new signature with the received one --->
                <cfif urlsafeB64Decode( local.testSignature ) neq local.signature>

                    <cfthrow type="Application" message="sigFailed">
                </cfif>
            </cfif>

            <cfreturn local.payload>

            <cfcatch type="any">
                <cfswitch expression="#cfcatch.message#">

                    <cfcase value="invalidSegmentCount">
                        <cfoutput>Wrong nubmber of segments</cfoutput>
                    </cfcase>

                    <cfcase value="noAlgor">
                        <cfoutput>No algorithm defined in header</cfoutput>
                    </cfcase>

                    <cfcase value="sigFailed">
                        <cfoutput>Signature verification failed</cfoutput>
                    </cfcase>

                    <cfdefaultcase>
                        <cfoutput>#cfcatch.message#</cfoutput>
                    </cfdefaultcase>

                </cfswitch>
                <!--- no return, abort request --->
                <cfabort />
            </cfcatch>
        </cftry>

    </cffunction>

    <!---
        Sign a string with a given key and algorithm
     --->
    <cffunction name="sign" access="private" returntype="Any">
        <!--- ****************** Arguments ************************ --->
        <cfargument name="msg" type="string" required="true" hint="the message to sign">
        <cfargument name="key" type="string" required="true" hint="the secret key">
        <cfargument name="method" type="string" required="true" hint="the signing algorithm. We only use hcmacSHA256 right because that is suggested in JWT draft">
        <!--- ****************** /Arguments *********************** --->

        <cfset local.hashmac        = CFHashMac( Arguments.msg, Arguments.key, Arguments.method )>

        <!---
            replace + and - characters and remove padding ( = )
        --->
        <cfset local.hashmac        = replace( local.hashmac, "+", "-", "all")>
        <cfset local.hashmac        = replace( local.hashmac, "/", "_", "all")>
        <cfset local.hashmac        = replace( local.hashmac, "=", "", "all")>

        <cfreturn local.hashmac>

    </cffunction>

    <!---
        UrlSafeBinary64 encoding function that will replace return the +/ characters and apply padding
     --->
    <cffunction name="urlsafeB64Decode" access="private" returntype="Any">
        <!--- ****************** Arguments ************************ --->
        <cfargument name="input" required="true">
        <!--- ****************** /Arguments *********************** --->

        <!---
            return non websafe characters
        --->
        <cfset Arguments.input      = replace( Arguments.input, "-", "+", "all")>
        <cfset Arguments.input      = replace( Arguments.input, "_", "/", "all")>

        <cfset local.remainder      = len( Arguments.input ) mod 4>
        <!---
            add padding to input string so that it is a valid base64 format
        --->
        <cfif local.remainder Gt 0>
            <cfset local.padlen     = 4 - local.remainder>
            <cfset Arguments.input  = Arguments.input & RepeatString( "=", local.padlen )>
        </cfif>

        <cfset local.binaryValue    = binaryDecode( Arguments.input, "base64" )>
        <cfset local.stringValue    = toString( local.binaryValue )>

        <cfreturn local.stringValue>

    </cffunction>

    <!---
        Generate a keyed hashvalue using the HMAC method
     --->
    <cffunction name="CFHashMac" output="true" returntype="string">
        <!--- ****************** Arguments ************************ --->
        <cfargument name="msg" type="string" required="true" />
        <cfargument name="key" type="string" required="true" />
        <cfargument name="method" type="string" required="true" />
        <!--- ****************** /Arguments *********************** --->

        <cfswitch expression="#Arguments.method#">
            <cfcase value="HS256">
                <cfset local.algor  = "HmacSHA256">
            </cfcase>

            <cfdefaultcase>
                <cfset local.algor  = "HmacSHA256">
            </cfdefaultcase>

        </cfswitch>

       <cfset local.key             = createObject("java", "javax.crypto.spec.SecretKeySpec").init(
            Arguments.key.getBytes( Variables.encoding ), local.algor
        ) />

       <cfset local.mac             = createObject("java", "javax.crypto.Mac" ).getInstance( local.algor ) />
       <cfset local.mac.init( local.key ) />

       <cfreturn toBase64(
            local.mac.doFinal(
                Arguments.msg.getBytes( Variables.encoding )
            )
       ) />

    </cffunction>

    <!---
        Return current UTC time in seconds
     --->
    <cffunction name="getCurrentUtcTime" returntype="Numeric" access="private">

        <cfset local.currentDate = Now()>
        <cfset local.utcDate = dateConvert( "local2utc", local.currentDate )>

        <cfreturn round( local.utcDate.getTime() / 1000 )>

    </cffunction>

</cfcomponent>