#use 5.008008;
use 5.006;
use ExtUtils::MakeMaker qw(prompt WriteMakefile);
use Config;
use strict;

my $name = 'Linux-DVB-DVBT-TS' ;

my $mod = $name ;
$mod =~ s%\-%::%g ;

my $modpath = $name ;
$modpath =~ s%\-%/%g ;


## Check OS
##
##    *  No support for OS
##    * OS unsupported 
#if ($^O !~ /linux/i)
#{
#	print "No support for OS\n" ;
#	exit 1 ;
#}

# See if newer version is available
check_new_version() ;


my @programs_to_install = qw(dvbt-ts-repair dvbt-ts-pics dvbt-ts-cut);
my $install_bin = 1;

if ( 
	grep $_ eq '-n', @ARGV
	or grep /^LIB=/, @ARGV and not grep /^INSTALLSCRIPT=/, @ARGV 
) 
{
	@ARGV = grep $_ ne '-n', @ARGV;
	warn "Skipping installation of scripts...\n";
	@programs_to_install = ();
} 
else 
{
	warn <<EOW;

This Perl module comes with several scripts which I would try to install in
directory $Config{installscript}.

To skip install, rerun with option -n given to Makefile.PL.

EOW
}


# -d = debug 
my $MOD_DEFINE="-DHAVE_MPEG2 -DHAVE_AUDIO" ;
my $MAKE_DEFINE="HAVE_MPEG2=1 HAVE_AUDIO=1" ;
if ( 
	grep $_ eq '-d', @ARGV
) 
{
	@ARGV = grep $_ ne '-d', @ARGV;
	warn "Buidling version with extra debugging enabled...\n";
	$MOD_DEFINE .= " -DDEBUG" ;
	$MAKE_DEFINE .= " DEBUG=1" ;
} 



# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => $mod,
    VERSION_FROM      => "lib/$modpath.pm", # finds $VERSION
    PREREQ_PM         => {
		'File::Basename'	=> 0,
		'File::Path' 		=> 0,
		'File::Spec' 		=> 0,
		'POSIX'			=> 0,
		'Test::Pod::Coverage'	=> 1.08,
		'Pod::Coverage' => 0.18,
		'Test::Pod' => 1.22,
    }, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => "lib/$modpath.pm", # retrieve abstract from module
       AUTHOR         => 'Steve Price <cpan@sdprice.plus.com>') : ()),
    LIBS              => ['-lrt'], # e.g., '-lm'
    DEFINE            => $MOD_DEFINE, # e.g., '-DHAVE_SOMETHING'
    INC               => '-I./clib/dvb_ts_lib -I./clib/dvb_lib -I./clib/libmpeg2/include -I./clib/mpeg2audio', # e.g., '-I. -I/usr/include/other'
    EXE_FILES         => [ map "script/$_", @programs_to_install ],
 
 
    ##CCFLAGS			  => '-g -O0',
    OPTIMIZE	  => '-ggdb',
	# Un-comment this if you add C files to link with later:
    # OBJECT            => '$(O_FILES)', # link all the C files too

    MYEXTLIB          => 'clib/dvb_ts_lib/libdvb_ts_lib$(LIB_EXT)', 

);

## ADDED SDP
sub MY::postamble {
'
# If make is called with TESTDEF defined then it passes this definition down to the library build to allow
# special test builds
MAKE_TEST_DEF=
ifdef TESTDEF
	MAKE_TEST_DEF="TESTDEF=$(TESTDEF)"
endif

## make libs
$(MYEXTLIB): clib/dvb_ts_lib/Makefile 
	cd clib/dvb_ts_lib && $(MAKE) $(MAKE_TEST_DEF) '.$MAKE_DEFINE.' CCFLAGS="$(CCFLAGS)" CCCDLFLAGS="$(CCCDLFLAGS)"

## Clean up
clean:: dvb_lib_clean                                                                                                   
                                                                                                                        
dvb_lib_clean: FORCE                                                                                                    
	cd clib/dvb_ts_lib && $(MAKE) clean                                                                                     

## Optional doxygen documentation 
doxygen: FORCE
	cd doxygen && doxygen

## Author target: preview CPAN documentation
cpandoc: FORCE
	perl -MPod::Simple::HTMLBatch -e Pod::Simple::HTMLBatch::go . pod/batch
	cp pod/html_files/style.css pod/batch/_black_with_blue_on_white.css

';
}


sub check_new_version
{
	my $version = ExtUtils::MM_Unix->parse_version("lib/$modpath.pm");

	print "Installing Version: $version\n" ;
	
	## Check for newer version
	eval {
		require LWP::UserAgent;
	} ;
	if (!$@)
	{
		print "Checking for later version...\n" ;
		
		## specify user name so that I can filter out my builds
		my $user = $ENV{USER} || $ENV{USERNAME} || 'nobody' ;

		# CPAN testers
		my $cpan = $ENV{'PERL5_CPAN_IS_RUNNING'}||0 ;
		
		## check for OS-specific versions
		my $os = $^O ;
		my $url = "http://quartz.homelinux.com/CPAN/index.php?ver=$version&mod=$name&user=$user&os=$os&cpan=$cpan" ;
		 
		my $ua = LWP::UserAgent->new;
		$ua->agent("CPAN-$name/$version") ;
		$ua->timeout(10);
		$ua->env_proxy;
		 
		my $response = $ua->get($url);
		if ($response->is_success) 
		{
			my $content = $response->content ;
			if ($content =~ m/Current version : ([\d\.]+)/m)
			{
				print "Latest CPAN version is $1\n" ;
			}
			if ($content =~ m/Newer version/m)
			{
				print "** NOTE: A newer version than this is available. Please downloaded latest version **\n" ;
			}
			else
			{
				print "Got latest version\n" ;
			}
		}
		else
		{
			print "Unable to connect, assuming latest\n" ;
			#print $response->status_line;
		}
	}
	
}
