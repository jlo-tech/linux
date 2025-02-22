#include <crypto/hash.h>
#include <linux/syscalls.h>
#include <linux/hashtable.h>

#include <linux/blacklist.h>

#define SHA256_HASH_SIZE 32

struct blacklist_struct {
	unsigned long hkey;				// key for hashtable
	struct hlist_node hnode;
	unsigned char hash[SHA256_HASH_SIZE];		// actual hash
};

DEFINE_HASHTABLE(hht, 9);

void blacklist_init()
{
	hash_init(hht);
}

static int compute_file_sha256(unsigned char *buf, size_t size, unsigned char *hash)
{
	struct crypto_shash *alg = crypto_alloc_shash("sha256", 0, 0);

	struct shash_desc *sdesc = kmalloc(
		sizeof(struct shash_desc) +
		crypto_shash_descsize(alg),
		GFP_KERNEL);
	if(!sdesc) {
		return -ENOMEM;
	}
	sdesc->tfm = alg;

	// Do actual hashing
	crypto_shash_digest(sdesc, buf, size, hash);

	crypto_free_shash(alg);

	return 0;
}

static int blacklist_hash(struct filename *fname, unsigned char *hash)
{
	if(!fname) {
		return -ENOENT;
	}

	// Open file by path
	struct file *f = file_open_name(fname, O_RDONLY, 0);
	if(IS_ERR(f)) {
		return -ENOENT;
	}

	// Determine file size
	loff_t sz = f->f_inode->i_size;

	unsigned char *buf = vmalloc(sz);

	// Copy exe into mem
	loff_t pos = 0;
	kernel_read(f, buf, sz, &pos); // TODO: Add read loop

	int retval = compute_file_sha256(buf, sz, hash);
	if(retval < 0) {
		return retval;
	}

	vfree(buf);

	filp_close(f, NULL);

	return 0;
}

static unsigned long hash_to_hkey(unsigned char *hash)
{
	unsigned long ret = 0;
	for(int i = 0; i < sizeof(unsigned long); i++)
	{
		ret = (ret << 8) | hash[i];
	}
	return ret;
}

static bool blacklist_contains_hash(unsigned char *hash)
{
	struct blacklist_struct *ptr;

	unsigned long key = hash_to_hkey(hash);

	hash_for_each_possible(hht, ptr, hnode, key) {
		if(memcmp(hash, ptr->hash, SHA256_HASH_SIZE) == 0) {
			return true;
		}
	}

	return false;
}

/**
 * blacklist_validate - Check if a file was blacklisted
 */
bool blacklist_validate(struct filename *fname)
{
	unsigned char hash[SHA256_HASH_SIZE];
	blacklist_hash(fname, hash);
	return !blacklist_contains_hash(hash);
}

/**
 *  blacklist_block - Add hash to be blocked
 */
static int blacklist_block(unsigned char *hash)
{
	struct blacklist_struct *bl_struct = kmalloc(sizeof(struct blacklist_struct), GFP_KERNEL);
	if(!bl_struct)
		return -ENOMEM;

	bl_struct->hkey = hash_to_hkey(hash);
	memcpy(bl_struct->hash, hash, SHA256_HASH_SIZE);

	hash_add(hht, &bl_struct->hnode, bl_struct->hkey);

	return 0;
}

/**
 * do_blacklist - Syscall to add hash to be blocked
 */
static long do_blacklist(unsigned char *uhash)
{
	if(current_euid().val != 0) {
		pr_info("BLACKLIST: You need to be root to execute sys_blacklist().");
		return -EPERM;
	}

	unsigned char khash[32];
	int retval = copy_from_user(khash, uhash, SHA256_HASH_SIZE);
	if(retval > 0)
		return -EFAULT;

	blacklist_block(khash);

	return 0;
}

SYSCALL_DEFINE1(blacklist, unsigned char __user *, uhash)
{
	return do_blacklist(uhash);
}
