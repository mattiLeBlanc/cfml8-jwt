<!---
    Example of using cfml-jwt component to encode and decode in plaintext

    Author:         Mattijs Spierings
    Date:           13/5/2014
--->

 <cfscript>
/*
    Create our component and preset some of the required JWT fields. ISS and AUD will automatically be added to the payload while decoding.
*/
    Variables.JWT = createObject( "component", "cfml-jwt" ).init(
        iss                         = "the issuer party"
    ,   aud                         = "the audience"
    ,   exp                         = 3600
    );

    Variables.secretKey             = "example_key";

/*-----------------------------------------------------------------------------------------------------------------
                                                Encoding example
-----------------------------------------------------------------------------------------------------------------*/

    // create our plainttext payload
    //
    Variables.payload                 = StructNew();
    Variables.payload[ "subject" ]    = "parcels";
    Variables.payload[ "count" ]      = 3;

    // create our token
    //
                                        // JWT.encode( object payload, string secretKey, string algorithm:not required )
    Variables.result                  = JWT.encode( payload, Variables.secretKey );

    // let's see it
    //
    writeOutput( "The generated JWT:" );
    writeOutput( "<pre style='white-space: pre-wrap;'>" );
    writeOutput( Variables.result );
    writeOutput( "</pre>" );

/*-----------------------------------------------------------------------------------------------------------------
                                                Decoding example
-----------------------------------------------------------------------------------------------------------------*/

    // if queryparam jwt does not exists, use jwt created in encoding example above
    //
    if ( StructKeyExists( Url, "jwt" ) )
    {
        Variables.jwtStr              = Url.jwt;
    }
    else
    {
        Variables.jwtStr              = Variables.result;
    }
                                        // JWT.decode( string jwt, string secretKey, bool verifySignature )
    Variables.decoded                 = JWT.decode( Variables.jwtStr , Variables.secretKey, true );

    // let's see the package
    //
    writeOutput( "The decoded payload" );
    dump( decoded );
 </cfscript>

<!------------------------------------------------------------------------------------------------------------------->


<!---
    annoyingly CFML8 doesnt support dump in cfscript
 --->
 <cffunction name="dump" access="public" returntype="void">
     <cfargument name="value" type="any" required="true">
     <cfdump var="#Arguments.value#">
 </cffunction>