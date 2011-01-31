// VERSION = "1.000"
//
// Standard C code loaded outside XS space. Contains useful routines used by ts TS parsing functions

#include "ts_split.h"

//========================================================================================================
// SPLIT
//========================================================================================================

//---------------------------------------------------------------------------------------------------------
//
static void next_split_file(struct TS_cut_data *hook_data)
{
	// close currently open
	if (hook_data->cut_file)
	{
		close(hook_data->cut_file) ;
		hook_data->cut_file = 0 ;
	}

	// open next
	{
	char cutname[256] ;

		sprintf(cutname, "%s-%04u.ts",
				hook_data->ofname, ++hook_data->split_count) ;

		hook_data->cut_file = open(cutname, O_CREAT | O_TRUNC | O_WRONLY | O_LARGEFILE, 0666);

		if (hook_data->debug >= 10) printf("-> save cut sequence: %s [%d]\n", cutname, hook_data->cut_file) ;
	}

}

//---------------------------------------------------------------------------------------------------------
// void (*tsparse_ts_hook)(unsigned long, unsigned, const uint8_t *, unsigned, unsigned, unsigned) ;
static void ts_split_hook(struct TS_pidinfo *pidinfo, uint8_t *packet, unsigned packet_len, void *user_data)
{
struct TS_cut_data *hook_data = (struct TS_cut_data *)user_data ;
static unsigned prev_ok=1;
unsigned ok = 1 ;

	if (hook_data->debug >= 10)
	{
		printf("-> TS PID 0x%x (%u) [%u] :: start=%d err=%d\n",
				pidinfo->pid, pidinfo->pid,
				pidinfo->pktnum,
				pidinfo->pes_start ? 1 : 0,
				pidinfo->pid_error ? 1 : 0) ;
	}

	// check cut
	if (hook_data->current_cut == UNSET_CUT_LIST)
	{
	struct list_head *item;

		list_for_each(item, hook_data->cut_list)
		{
			hook_data->current_cut = list_entry(item, struct TS_cut, next);
			next_split_file(hook_data) ;
			break;
		}
	}

	if (hook_data->current_cut != END_CUT_LIST)
	{
		// check current
		if (pidinfo->pktnum < hook_data->current_cut->start)
		{
			// still before start of next band
		}
		else
		{
			// still before (or at) end of this current band
			if (pidinfo->pktnum <= hook_data->current_cut->end)
			{
				// cut, in this cut band
				ok = 0 ;

				if (prev_ok)
				{
					if (hook_data->debug) printf("Skipping %u .. %u\n", hook_data->current_cut->start, hook_data->current_cut->end) ;
				}

				prev_ok = ok ;

			}
			else
			{
			struct list_head *item;

				// ok, beyond this cut band - find next cut region
				do
				{
					list_next_each(hook_data->current_cut, END_CUT_LIST, item, hook_data->cut_list)
					{
						hook_data->current_cut = list_entry(item, struct TS_cut, next);
						break;
					}
				} while ( (hook_data->current_cut != END_CUT_LIST) && (pidinfo->pktnum > hook_data->current_cut->start) ) ;

				prev_ok=1;

				// save next band into new file
				next_split_file(hook_data) ;
			}
		}
	}

	if (hook_data->debug)
	{
		printf("-> TS PID 0x%x (%u) [%u] :: ok=%d\n",
				pidinfo->pid, pidinfo->pid,
				pidinfo->pktnum,
				ok) ;
	}

	// write if allowed to
	if (hook_data->cut_file)
	{
		write(hook_data->cut_file, packet, packet_len);
	}
}



//---------------------------------------------------------------------------------------------------------
int ts_split(char *filename, char *ofilename, struct list_head *cuts_array, unsigned debug)
{
int file;
struct TS_cut_data hook_data ;
struct TS_reader *tsreader ;

	hook_data.cut_list = cuts_array ;

	hook_data.current_cut = UNSET_CUT_LIST ;
	hook_data.debug = debug ;
	hook_data.ofile = 0 ;
	hook_data.split_count = 0 ;
	hook_data.cut_file = 0 ;
    hook_data.ofile = 0 ;

	tsreader = tsreader_new(filename) ;
    if (!tsreader)
    {
    	return(dvb_error_code);
    }
	tsreader->ts_hook = ts_split_hook ;
	tsreader->user_data = &hook_data ;
	tsreader->debug = debug ;

	strcpy(hook_data.fname, filename) ;
	char *p = rindex(hook_data.fname, '.') ;
	*p=0 ;

	strcpy(hook_data.ofname, ofilename) ;
	p = rindex(hook_data.ofname, '.') ;
	*p=0 ;

	// parse data
    ts_parse(tsreader) ;

    if (hook_data.cut_file)
    	close(hook_data.cut_file) ;

	tsreader_free(tsreader) ;
	free_cut_list(hook_data.cut_list) ;

	return(dvb_error_code) ;
}


