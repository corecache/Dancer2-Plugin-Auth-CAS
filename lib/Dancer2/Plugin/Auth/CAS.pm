package Dancer2::Plugin::Auth::CAS;
 
use strict;
use warnings;

use Dancer2::Plugin;
use Dancer2::Core::Error;
use Authen::CAS::Client;
 
plugin_keywords 'auth_cas';
 
sub BUILD {
    my $plugin = shift;
}
 
sub auth_cas {
    my( $plugin, %options ) = @_;

    my $config = $plugin->config;
    my $app = $plugin->app;

    my $base_url = $config->{cas_url} // $plugin->dsl->send_error("cas_url is unset" );
    my $cas_version = $config->{cas_version} ||  $plugin->dsl->send_error("cas_version is unset");
    my $cas_user_map = $config->{cas_user_map} || 'cas_user';
    my $cas_denied_url = $config->{cas_denied_path} || '/denied'; 

    my $ssl_verify_hostname = $config->{ssl_verify_hostname};
    $ENV{"PERL_LWP_SSL_VERIFY_HOSTNAME"} = defined( $ssl_verify_hostname ) ? $ssl_verify_hostname : 1;

    # check supported versions
    unless( grep(/$cas_version/, qw( 2.0 1.0 )) ) {
        $plugin->dsl->send_error( message => "cas_version '$cas_version' not supported");
    }

    my $mapping = $config->{cas_attr_map} || {};
 
    my $ticket = $options{ticket};
    my $params = $plugin->dsl->params;
    unless( $ticket ) {
        my $tickets = $params->{ticket};
        # For the case when application also uses 'ticket' parameters
        # we only remove the real cas service ticket
        if( ref($tickets) eq "ARRAY" ) {
            while( my ($index, $value) = each @$tickets ) {
                # The 'ST-' is specified in CAS-protocol
                if( $value =~ m/^ST\-/ ) {
                    $ticket = delete $tickets->[$index];
                }
            }
        } else {
            $ticket = delete $params->{ticket};
        }
    }
    my $service = $plugin->dsl->uri_for( $plugin->app->request->path_info, $params );
 
    my $cas = Authen::CAS::Client->new( $base_url );
 
    my $user = $plugin->dsl->session($cas_user_map);

    unless( $user ) {
 
        my $response = Dancer2::Core::Response->new( status => 302 );
        my $redirect_url;
 
        if( $ticket) {
            $plugin->dsl->debug("Trying to validate via CAS '$cas_version' with ticket=$ticket");
             
            my $r;
            if( $cas_version eq "1.0" ) {
                $r = $cas->validate( $service, $ticket );
            }
            elsif( $cas_version eq "2.0" ) {
                $r = $cas->service_validate( $service, $ticket );
            }
            else {
                $plugin->dsl->send_error( message => "cas_version '$cas_version' not supported");
            }
 
            if( $r->is_success ) {
 
                # Redirect to given path
                $plugin->dsl->info("Authenticated as: ".$r->user);
                if( $cas_version eq "1.0" ) {
                    $plugin->dsl->session($cas_user_map => $r->user);
                } else {
                    $plugin->dsl->session($cas_user_map => _map_attributes( $r->doc, $mapping ));
                }
                $plugin->dsl->debug("Mapped attributes: ".$plugin->dsl->to_dumper( $plugin->dsl->session($cas_user_map) ));
                $redirect_url = $service;
 
            } elsif( $r->is_failure ) {
 
                # Redirect to denied
                $plugin->dsl->debug("Failed to authenticate: ".$r->code." / ".$r->message);
                $redirect_url = $plugin->dsl->uri_for( $cas_denied_url );
 
            } else {
 
                # Raise hard error, backend has errors
                $plugin->dsl->error("Unable to authenticate: ".$r->error);
                $plugin->dsl->send_error("Unable to authenticate: ".$r->error);
            }
 
        } else {
            # Has no ticket, needs one
            $plugin->dsl->debug("Redirecting to CAS: ".$cas->login_url( $service ));
            $redirect_url = $cas->login_url( $service );
        }
 
        # General redir response
        $plugin->dsl->redirect( $redirect_url );
    }

}

sub _map_attributes {
    my ( $doc, $mapping ) = @_;
 
    my $attrs = {};
 
    my $result = $doc->find( '/cas:serviceResponse/cas:authenticationSuccess' );
    if( $result ) { 
        my $node = $result->get_node(1);
 
        # extra all attributes
        my @attributes = $node->findnodes( "./cas:attributes/*" );
        foreach my $a (@attributes) {
            my $name = (split(/:/, $a->nodeName, 2))[1];
            my $val = $a->textContent;
 
            my $mapped_name = $mapping->{ $name } // $name;
            $attrs->{ $mapped_name } = $val;
        }
             
    }
    return $attrs;
}
 
1;
