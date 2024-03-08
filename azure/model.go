package azure

import "time"

type GetApplicationResponse struct {
	OdataContext                      string        `json:"@odata.context"`
	ID                                string        `json:"id"`
	DeletedDateTime                   interface{}   `json:"deletedDateTime"`
	AppID                             string        `json:"appId"`
	ApplicationTemplateID             interface{}   `json:"applicationTemplateId"`
	DisabledByMicrosoftStatus         interface{}   `json:"disabledByMicrosoftStatus"`
	CreatedDateTime                   time.Time     `json:"createdDateTime"`
	DisplayName                       string        `json:"displayName"`
	Description                       interface{}   `json:"description"`
	GroupMembershipClaims             interface{}   `json:"groupMembershipClaims"`
	IdentifierUris                    []string      `json:"identifierUris"`
	IsDeviceOnlyAuthSupported         interface{}   `json:"isDeviceOnlyAuthSupported"`
	IsFallbackPublicClient            interface{}   `json:"isFallbackPublicClient"`
	Notes                             interface{}   `json:"notes"`
	PublisherDomain                   string        `json:"publisherDomain"`
	ServiceManagementReference        interface{}   `json:"serviceManagementReference"`
	SignInAudience                    string        `json:"signInAudience"`
	Tags                              []interface{} `json:"tags"`
	TokenEncryptionKeyID              interface{}   `json:"tokenEncryptionKeyId"`
	SamlMetadataURL                   interface{}   `json:"samlMetadataUrl"`
	DefaultRedirectURI                interface{}   `json:"defaultRedirectUri"`
	Certification                     interface{}   `json:"certification"`
	OptionalClaims                    interface{}   `json:"optionalClaims"`
	ServicePrincipalLockConfiguration interface{}   `json:"servicePrincipalLockConfiguration"`
	RequestSignatureVerification      interface{}   `json:"requestSignatureVerification"`
	AddIns                            []interface{} `json:"addIns"`
	API                               struct {
		AcceptMappedClaims          interface{}   `json:"acceptMappedClaims"`
		KnownClientApplications     []interface{} `json:"knownClientApplications"`
		RequestedAccessTokenVersion interface{}   `json:"requestedAccessTokenVersion"`
		Oauth2PermissionScopes      []struct {
			AdminConsentDescription string `json:"adminConsentDescription"`
			AdminConsentDisplayName string `json:"adminConsentDisplayName"`
			ID                      string `json:"id"`
			IsEnabled               bool   `json:"isEnabled"`
			Type                    string `json:"type"`
			UserConsentDescription  string `json:"userConsentDescription"`
			UserConsentDisplayName  string `json:"userConsentDisplayName"`
			Value                   string `json:"value"`
		} `json:"oauth2PermissionScopes"`
		PreAuthorizedApplications []interface{} `json:"preAuthorizedApplications"`
	} `json:"api"`
	AppRoles []struct {
		AllowedMemberTypes []string `json:"allowedMemberTypes"`
		Description        string   `json:"description"`
		DisplayName        string   `json:"displayName"`
		ID                 string   `json:"id"`
		IsEnabled          bool     `json:"isEnabled"`
		Origin             string   `json:"origin"`
		Value              string   `json:"value"`
	} `json:"appRoles"`
	Info struct {
		LogoURL             interface{} `json:"logoUrl"`
		MarketingURL        interface{} `json:"marketingUrl"`
		PrivacyStatementURL interface{} `json:"privacyStatementUrl"`
		SupportURL          interface{} `json:"supportUrl"`
		TermsOfServiceURL   interface{} `json:"termsOfServiceUrl"`
	} `json:"info"`
	KeyCredentials          []interface{} `json:"keyCredentials"`
	ParentalControlSettings struct {
		CountriesBlockedForMinors []interface{} `json:"countriesBlockedForMinors"`
		LegalAgeGroupRule         string        `json:"legalAgeGroupRule"`
	} `json:"parentalControlSettings"`
	PasswordCredentials []struct {
		CustomKeyIdentifier interface{} `json:"customKeyIdentifier"`
		DisplayName         string      `json:"displayName"`
		EndDateTime         time.Time   `json:"endDateTime"`
		Hint                string      `json:"hint"`
		KeyID               string      `json:"keyId"`
		SecretText          interface{} `json:"secretText"`
		StartDateTime       time.Time   `json:"startDateTime"`
	} `json:"passwordCredentials"`
	PublicClient struct {
		RedirectUris []interface{} `json:"redirectUris"`
	} `json:"publicClient"`
	RequiredResourceAccess []struct {
		ResourceAppID  string `json:"resourceAppId"`
		ResourceAccess []struct {
			ID   string `json:"id"`
			Type string `json:"type"`
		} `json:"resourceAccess"`
	} `json:"requiredResourceAccess"`
	VerifiedPublisher struct {
		DisplayName         interface{} `json:"displayName"`
		VerifiedPublisherID interface{} `json:"verifiedPublisherId"`
		AddedDateTime       interface{} `json:"addedDateTime"`
	} `json:"verifiedPublisher"`
	Web struct {
		HomePageURL           interface{}   `json:"homePageUrl"`
		LogoutURL             interface{}   `json:"logoutUrl"`
		RedirectUris          []interface{} `json:"redirectUris"`
		ImplicitGrantSettings struct {
			EnableAccessTokenIssuance bool `json:"enableAccessTokenIssuance"`
			EnableIDTokenIssuance     bool `json:"enableIdTokenIssuance"`
		} `json:"implicitGrantSettings"`
		RedirectURISettings []interface{} `json:"redirectUriSettings"`
	} `json:"web"`
	Spa struct {
		RedirectUris []string `json:"redirectUris"`
	} `json:"spa"`
}

type PatchApplicationSpaRedirectUri struct {
	Spa PatchApplicationSpaRedirectUriSpa `json:"spa"`
}

type PatchApplicationSpaRedirectUriSpa struct {
	RedirectUris []string `json:"redirectUris"`
}
