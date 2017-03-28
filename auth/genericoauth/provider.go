package genericoauth

import (
	"errors"
	"net/http"

	"code.cloudfoundry.org/lager"

	"github.com/concourse/atc/auth/provider"
	"github.com/concourse/atc/auth/verifier"
	"github.com/concourse/atc/db"
	"github.com/hashicorp/go-multierror"
	flags "github.com/jessevdk/go-flags"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
)

const ProviderName = "oauth"

type Provider struct {
	verifier.Verifier
	Config ConfigOverride
}

type ConfigOverride struct {
	oauth2.Config
	AuthURLParams map[string]string
}

type NoopVerifier struct{}

func init() {
	provider.Register(ProviderName, GenericTeamProvider{})
}

type GenericOAuthFlag struct {
	DisplayName   string            `long:"display-name"   description:"Name for this auth method on the web UI."`
	ClientID      string            `long:"client-id"      description:"Application client ID for enabling generic OAuth."`
	ClientSecret  string            `long:"client-secret"  description:"Application client secret for enabling generic OAuth."`
	AuthURL       string            `long:"auth-url"       description:"Generic OAuth provider AuthURL endpoint."`
	AuthURLParams map[string]string `long:"auth-url-param" description:"Parameter to pass to the authentication server AuthURL. Can be specified multiple times."`
	Scope         string            `long:"scope"          description:"Optional scope required to authorize user"`
	TokenURL      string            `long:"token-url"      description:"Generic OAuth provider TokenURL endpoint."`
}

func (auth *GenericOAuthFlag) IsConfigured() bool {
	return auth.AuthURL != "" ||
		auth.TokenURL != "" ||
		auth.ClientID != "" ||
		auth.ClientSecret != "" ||
		auth.DisplayName != ""
}

func (auth *GenericOAuthFlag) Validate() error {
	var errs *multierror.Error
	if auth.ClientID == "" || auth.ClientSecret == "" {
		errs = multierror.Append(
			errs,
			errors.New("must specify --generic-oauth-client-id and --generic-oauth-client-secret to use Generic OAuth."),
		)
	}
	if auth.AuthURL == "" || auth.TokenURL == "" {
		errs = multierror.Append(
			errs,
			errors.New("must specify --generic-oauth-auth-url and --generic-oauth-token-url to use Generic OAuth."),
		)
	}
	if auth.DisplayName == "" {
		errs = multierror.Append(
			errs,
			errors.New("must specify --generic-oauth-display-name to use Generic OAuth."),
		)
	}
	return errs.ErrorOrNil()
}

type GenericTeamProvider struct{}

func (GenericTeamProvider) AddAuthGroup(parser *flags.Parser) {
	parser.Group.AddGroup("Generic Auth", "Generic Authentication", GenericOAuthFlag{})
}

func (GenericTeamProvider) ProviderConfigured(team db.Team) bool {
	return team.GenericOAuth != nil
}

func (GenericTeamProvider) ProviderConstructor(
	team db.SavedTeam,
	redirectURL string,
) (provider.Provider, bool) {

	if team.GenericOAuth == nil {
		return nil, false
	}

	endpoint := oauth2.Endpoint{}
	if team.GenericOAuth.AuthURL != "" && team.GenericOAuth.TokenURL != "" {
		endpoint.AuthURL = team.GenericOAuth.AuthURL
		endpoint.TokenURL = team.GenericOAuth.TokenURL
	}

	var oauthVerifier verifier.Verifier
	if team.GenericOAuth.Scope != "" {
		oauthVerifier = NewScopeVerifier(team.GenericOAuth.Scope)
	} else {
		oauthVerifier = NoopVerifier{}
	}

	return Provider{
		Verifier: oauthVerifier,
		Config: ConfigOverride{
			Config: oauth2.Config{
				ClientID:     team.GenericOAuth.ClientID,
				ClientSecret: team.GenericOAuth.ClientSecret,
				Endpoint:     endpoint,
				RedirectURL:  redirectURL,
			},
			AuthURLParams: team.GenericOAuth.AuthURLParams,
		},
	}, true
}

func (v NoopVerifier) Verify(logger lager.Logger, client *http.Client) (bool, error) {
	return true, nil
}

func (provider Provider) AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string {
	for key, value := range provider.Config.AuthURLParams {
		opts = append(opts, oauth2.SetAuthURLParam(key, value))

	}
	return provider.Config.AuthCodeURL(state, opts...)
}

func (provider Provider) Exchange(ctx context.Context, code string) (*oauth2.Token, error) {
	return provider.Config.Exchange(ctx, code)
}

func (provider Provider) Client(ctx context.Context, t *oauth2.Token) *http.Client {
	return provider.Config.Client(ctx, t)
}

func (Provider) PreTokenClient() (*http.Client, error) {
	return &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: true,
		},
	}, nil
}
