import { Injectable } from '@angular/core';
import { Http, Headers, Response } from '@angular/http';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';
import { CognitoUser, AuthenticationDetails, CognitoUserPool } from 'amazon-cognito-identity-js';
import * as AWS from 'aws-sdk';

// declare let AWS: any;
declare let apigClientFactory: any;

export interface Callback {
  cognitoCallback(message: string, result: any): void;
  cognitoCallbackWithCreds(message: string, result: any, creds: any, data: any): void;
  googleCallback(creds: any, profile: any);
  googleCallbackWithData(data: any);
  testCallback(result: any, err: any);
}

@Injectable()
export class AwsService {
  token: any;
  googleCreds: any;
  googleProfile: any;
  googleData: any;
  userData: any;

  /************ RESOURCE IDENTIFIERS *************/
  appId = '500380957049008';
  googleId = '1003662980890-ggv0j02j601cds9t1ebs72nu27odkb9q.apps.googleusercontent.com';
  // Client ID 794565503646-c3v7uhi0da8n9cjb6nr80mbvt3pirgv6.apps.googleusercontent.com
  // Client Secret cboWkVmNQlRm1DQ76VKKNmVU
  poolData = {
    UserPoolId: 'us-east-1_khORGBgLC', // CognitoUserPool
    ClientId: '57na1p72e19ivknm9josoubfdc', // CognitoUserPoolClient
    Paranoia: 7
  };
  identityPool = 'us-east-1:eed487ba-f88c-46ee-b65a-cfb48596f60b'; // CognitoIdentityPool
  apiURL = 'XXXXXXXXXXXXXXXXXXXXXXXXXXX';  // ApiUrl
  region = 'us-east-1'; // Region Matching CognitoUserPool region

  /*********************************************/

  constructor(private _http: Http) {
    AWS.config.update({
      region: this.region,
      credentials: new AWS.CognitoIdentityCredentials({
        IdentityPoolId: ''
      })
    });
    AWS.config.region = this.region;
    AWS.config.update({ accessKeyId: 'null', secretAccessKey: 'null' });
  }

  setGoogleCreds(googleCreds) {
    this.googleCreds = googleCreds;
  }

  getgoogleCreds(callback) {
    callback.googleCallback(this.googleCreds);
    return this.googleCreds;
  }

  setGoogleProfile(googleProfile) {
    this.googleProfile = googleProfile;
  }

  getgoogleProfile(callback) {
    callback.googleCallback(this.googleProfile);
    return this.googleProfile;
  }

  getgoogleData(callback) {
    callback.googleCallback(this.googleCreds, this.getgoogleProfile);
    const googleData = {
      awsCreds: this.googleCreds,
      googleProfile: this.getgoogleProfile
    };
    return googleData;
  }


  authenticateGoogle(authResult, region, profile, callback) {
    // Add the Google access token to the Cognito credentials login map.
    AWS.config.credentials = new AWS.CognitoIdentityCredentials({
      IdentityPoolId: this.identityPool,
      Logins: {
        'accounts.google.com': authResult['id_token'] // graph.facebook.com
      }
    });

    // Obtain AWS credentials
    AWS.config.getCredentials(function () {
      // Access AWS resources here.
      const creds = {
        accessKey: AWS.config.credentials.accessKeyId,
        secretKey: AWS.config.credentials.secretAccessKey,
        sessionToken: AWS.config.credentials.sessionToken
      };
      const googleData = {
        awsCreds: creds,
        googleProfile: profile
      };
      callback.googleCallback(creds, profile);
    });

  }

  authenticateFb(authResult) {
    // Add the Google access token to the Cognito credentials login map.
    AWS.config.credentials = new AWS.CognitoIdentityCredentials({
      IdentityPoolId: this.identityPool,
      Logins: {
        'graph.facebook.com': authResult['accessToken'] // graph.facebook.com
      }
    });

    // Obtain AWS credentials
    AWS.config.getCredentials(function () {
      // Access AWS resources here.
      const creds = {
        accessKey: AWS.config.credentials.accessKeyId,
        secretKey: AWS.config.credentials.secretAccessKey,
        sessionToken: AWS.config.credentials.sessionToken
      };
      console.log(creds);
    });

  }

  userInfoApiGoogle(accessKey, secretKey, sessionToken, name, surname, email, region, callback) {
    const body = {
      name: name,
      surname: surname,
      email: email
    };

    let userData;
    const apigClient = apigClientFactory.newClient({
      accessKey: accessKey,
      secretKey: secretKey,
      sessionToken: sessionToken,
      region: region // The region where the API is deployed
    });
    apigClient.googlePost({}, body, {})
      .then(function (response) {
        console.log('Send user data to API');
      }).catch(function (response) {
        console.log(response);
      });
    apigClient.googleGet({}, {})
      .then(function (response) {
        console.log('Retrieve data from API');
        userData = response.data.Items[0];
        callback.googleCallbackWithData(userData);
      }).catch(function (response) {
        console.log(response);
      });
  }

  authenticateUserPool(user, password, callback) {
    const authenticationData = {
      Username: user,
      Password: password,
    };
    const authenticationDetails = new AuthenticationDetails(authenticationData);
    const userPool = new CognitoUserPool(this.poolData);
    const userData = {
      Username: user,
      Pool: userPool
    };
    const cognitoUser = new CognitoUser(userData);

    cognitoUser.authenticateUser(authenticationDetails, {
      onSuccess: function (result) {
        const cognitoGetUser = userPool.getCurrentUser();
        callback.cognitoCallback(null, result);
        if (cognitoGetUser != null) {
          cognitoGetUser.getSession(function (err, resultSet) {
            if (resultSet) {
              console.log('Authenticated to Cognito User Pools!');
            }
          });
        }
      },
      onFailure: function (err) {
        callback.cognitoCallback(err, null);
      }
    });
  }

  getInfoApiUserPools(token): Observable<any> {
    const headers = new Headers();
    headers.append('Content-Type', 'application/json');
    headers.append('Authorization', token);
    return this._http.get(this.apiURL + '/cup', { headers: headers })
      .pipe(map(res => res.json().Items[0]));

  }

  postInfoApiUserPools(token): Observable<any> {
    const headers = new Headers();
    const body = {};
    headers.append('Content-Type', 'application/json');
    headers.append('Authorization', token);
    return this._http.post(this.apiURL + '/cup', JSON.stringify(body), { headers: headers })
      .pipe(map(res => res.json()));
  }

  authenticateIdentityPool(user, password, region, callback) {
    const authenticationData = {
      Username: user,
      Password: password,
    };
    const authenticationDetails = new AuthenticationDetails(authenticationData);
    const userPool = new CognitoUserPool(this.poolData);
    const userData = {
      Username: user,
      Pool: userPool
    };
    const cognitoUser = new CognitoUser(userData);
    const cognitoParams = {
      IdentityPoolId: this.identityPool,
      Logins: {}
    };
    const poolId = this.poolData.UserPoolId;

    cognitoUser.authenticateUser(authenticationDetails, {
      onSuccess: function (result) {
        const cognitoGetUser = userPool.getCurrentUser();
        if (cognitoGetUser != null) {
          // tslint:disable-next-line:no-shadowed-variable
          cognitoGetUser.getSession(function (err, result) {
            if (result) {
              console.log('Authenticated to Cognito User and Identity Pools!');
              const token = result.getIdToken().getJwtToken();
              cognitoParams.Logins['cognito-idp.' + region + '.amazonaws.com/' + poolId] = token;
              AWS.config.credentials = new AWS.CognitoIdentityCredentials(cognitoParams);

              // Obtain AWS credentials
              AWS.config.getCredentials(function () {
                // Access AWS resources here.
                const creds = {
                  accessKey: AWS.config.credentials.accessKeyId,
                  secretKey: AWS.config.credentials.secretAccessKey,
                  sessionToken: AWS.config.credentials.sessionToken
                };
                const additionalParams = {
                  headers: {
                    Authorization: token
                  }
                };
                const params = {};
                let body = {};
                const apigClient = apigClientFactory.newClient({
                  accessKey: AWS.config.credentials.accessKeyId,
                  secretKey: AWS.config.credentials.secretAccessKey,
                  sessionToken: AWS.config.credentials.sessionToken,
                  region: region // The region where the API is deployed
                });
                const apigClientJWT = apigClientFactory.newClient();
                apigClientJWT.cipInfoGet({}, {}, additionalParams)
                  .then(function (response) {
                    body = response.data.Item;
                    console.log('Retrieving User Attributes from User Pool');
                    if (body != null) {
                      apigClient.cipPost({}, body, {})
                        .then(function (_response) {
                          console.log('Send user data to API');
                        }).catch(function (_response) {
                          console.log(_response);
                        });
                    }
                  }).catch(function (response) {
                    console.log(response);
                  });

                apigClient.cipGet(params, {})
                  .then(function (response) {
                    console.log('Retrieve data from API');
                    const data = response.data.Items[0];
                    callback.cognitoCallbackWithCreds(null, result, creds, data);
                  }).catch(function (response) {
                    console.log(response);
                  });
              });
            }
          });
        }
      },
      onFailure: function (err) {
        callback.cognitoCallback(err, null);
      }
    });

  }

  testAccess(data, provider, region, callback) {
    const apigClient = apigClientFactory.newClient({
      accessKey: data.accessKey,
      secretKey: data.secretKey,
      sessionToken: data.sessionToken,
      region: region // The region where the API is deployed
    });

    if (provider === 'google') {
      apigClient.googleGet({}, {})
        .then(function (response) {
          console.log(response);
          console.log('Access to /google API Resource with current credentials GRANTED');
          callback.testCallback(response, null);
        }).catch(function (response) {
          console.log(response);
          console.log('Access to /google API Resource with current credentials DENIED');
          callback.testCallback(null, response);
        });
    }

    if (provider === 'cup') {
      const apigwClient = apigClientFactory.newClient();
      const additionalParams = {
        headers: {
          Authorization: data.token
        }
      };
      apigwClient.cupGet({}, {})
        .then(function (response) {
          console.log(response);
          console.log('Access to /cup API Resource with current credentials GRANTED');
          callback.testCallback(response, null);
        }).catch(function (response) {
          console.log(response);
          console.log('Access to /cup API Resource with current credentials DENIED');
          callback.testCallback(null, response);
        });
    }

    if (provider === 'cip') {
      apigClient.cipGet({}, {})
        .then(function (response) {
          console.log(response);
          console.log('Access to /cip API Resource with current credentials GRANTED');
          callback.testCallback(response, null);
        }).catch(function (response) {
          console.log(response);
          console.log('Access to /cip API Resource with current credentials DENIED');
          callback.testCallback(null, response);
        });
    }
  }

  private _serverError(err: any) {
    console.log('sever error:', JSON.stringify(err));  // debug
    if (err.status === 0) {
      return Observable.throw(err.json().error || 'UNAUTHORIZED!!!');
    }
    if (err instanceof Response) {
      return Observable.throw(err.json().error || 'Backend Server Error');
    }
    // return Observable.throw(err || 'Backend Server Error');
  }

}
