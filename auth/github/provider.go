package github

import (
	"errors"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"

	"github.com/concourse/atc"
	"github.com/concourse/atc/auth/provider"
	"github.com/concourse/atc/auth/verifier"
	"github.com/concourse/atc/db"
	"github.com/hashicorp/go-multierror"
	flags "github.com/jessevdk/go-flags"
)

const ProviderName = "github"
const DisplayName = "GitHub"

var Scopes = []string{"read:org"}

type GitHubAuthFlag struct {
	ClientID      string               `long:"client-id"     description:"Application client ID for enabling GitHub OAuth."`
	ClientSecret  string               `long:"client-secret" description:"Application client secret for enabling GitHub OAuth."`
	Organizations []string             `long:"organization"  description:"GitHub organization whose members will have access." value-name:"ORG"`
	Teams         []atc.GitHubTeamFlag `long:"team"          description:"GitHub team whose members will have access." value-name:"ORG/TEAM"`
	Users         []string             `long:"user"          description:"GitHub user to permit access." value-name:"LOGIN"`
	AuthURL       string               `long:"auth-url"      description:"Override default endpoint AuthURL for Github Enterprise."`
	TokenURL      string               `long:"token-url"     description:"Override default endpoint TokenURL for Github Enterprise."`
	APIURL        string               `long:"api-url"       description:"Override default API endpoint URL for Github Enterprise."`
}

func (auth *GitHubAuthFlag) IsConfigured() bool {
	return auth.ClientID != "" ||
		auth.ClientSecret != "" ||
		len(auth.Organizations) > 0 ||
		len(auth.Teams) > 0 ||
		len(auth.Users) > 0
}

func (auth *GitHubAuthFlag) Validate() error {
	var errs *multierror.Error
	if auth.ClientID == "" || auth.ClientSecret == "" {
		errs = multierror.Append(
			errs,
			errors.New("must specify --github-auth-client-id and --github-auth-client-secret to use GitHub OAuth."),
		)
	}
	if len(auth.Organizations) == 0 && len(auth.Teams) == 0 && len(auth.Users) == 0 {
		errs = multierror.Append(
			errs,
			errors.New("at least one of the following is required for github-auth: organizations, teams, users."),
		)
	}
	return errs.ErrorOrNil()
}

// generic interface for auth flags (config)
type AuthConfig interface {
	IsConfigured() bool
	Validate() error
}

type GitHubProvider struct {
	*oauth2.Config
	verifier.Verifier
}

func init() {
	provider.Register(ProviderName, GitHubTeamProvider{})
}

type GitHubTeamProvider struct {
}

func (GitHubTeamProvider) AddAuthGroup(parser *flags.Parser) AuthConfig {
	// will return pointer to flags
	flags := &GitHubAuthFlag{}
	parser.Group.AddGroup("Github Auth", "Github Authentication", flags)
	return flags
}

func (GitHubTeamProvider) ProviderConfigured(team db.Team) bool {
	return team.GitHubAuth != nil
}

func (GitHubTeamProvider) ProviderConstructor(
	team db.SavedTeam,
	redirectURL string,
) (provider.Provider, bool) {

	if team.GitHubAuth == nil {
		return nil, false
	}

	client := NewClient(team.GitHubAuth.APIURL)

	endpoint := github.Endpoint
	if team.GitHubAuth.AuthURL != "" && team.GitHubAuth.TokenURL != "" {
		endpoint.AuthURL = team.GitHubAuth.AuthURL
		endpoint.TokenURL = team.GitHubAuth.TokenURL
	}

	return GitHubProvider{
		Verifier: verifier.NewVerifierBasket(
			NewTeamVerifier(DBTeamsToGitHubTeams(team.GitHubAuth.Teams), client),
			NewOrganizationVerifier(team.GitHubAuth.Organizations, client),
			NewUserVerifier(team.GitHubAuth.Users, client),
		),
		Config: &oauth2.Config{
			ClientID:     team.GitHubAuth.ClientID,
			ClientSecret: team.GitHubAuth.ClientSecret,
			Endpoint:     endpoint,
			Scopes:       Scopes,
			RedirectURL:  redirectURL,
		},
	}, true
}

func DBTeamsToGitHubTeams(dbteams []db.GitHubTeam) []Team {
	teams := []Team{}
	for _, team := range dbteams {
		teams = append(teams, Team{
			Name:         team.TeamName,
			Organization: team.OrganizationName,
		})
	}
	return teams
}

func (GitHubProvider) PreTokenClient() (*http.Client, error) {
	return &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: true,
		},
	}, nil
}
