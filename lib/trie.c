#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <string.h>




struct TrieNode* create_node() {
	
	struct TrieNode *new_node = malloc(sizeof(struct TrieNode));
	new_node->right = NULL;
	new_node->left = NULL;
    new_node->rt_entry = NULL;
    return new_node;
}

uint8_t get_mask_length(struct route_table_entry* rt_entry) {
    uint32_t mask = ntohl(rt_entry->mask);
    uint8_t count = 0;

    for(int i = 31; i >= 0; --i) {
        if ((mask & (1 << i)) != 0) {
            count++;
        }
    }
    return count;
}

void insert_ip(struct TrieNode *root, struct route_table_entry* rt_entry) {
    uint8_t mask_length = get_mask_length(rt_entry);

    uint32_t prefix = ntohl(rt_entry->prefix);
    struct TrieNode *root_copy = root;
    //computed the mask length 
    // now I have to go through every bit of the prefix and create whether 
    int i = 31;
    while (mask_length > 0) {
        //two cases I have bit 1 or 0
        if ((prefix & (1 << i)) == 0) {
            fprintf(stderr, "current bit is 0 ");
            //bit is 0 
            //now we have another two cases whether there is a node already or not 
            if (root_copy->left == NULL) {
                fprintf(stderr, "new node is created\n");
                // add new node 
                struct TrieNode* new_node = create_node();
                root_copy->left = new_node;
                root_copy = root_copy->left;
            }else {
                //just move to the next node 
                root_copy = root_copy->left;
            }
        } else {
            fprintf(stderr, "current bit is 1 ");
            //bit is 1
            if (root_copy->right == NULL) {
                fprintf(stderr, "new node is created \n");
                // add new node 
                struct TrieNode* new_node = create_node();
                root_copy->right = new_node;
                root_copy = root_copy->right;
            }else {
                //just move to the next node 
                root_copy = root_copy->right;
            }
        }
        mask_length--;
        i--;
    }
    root_copy->rt_entry = rt_entry;

}

struct TrieNode* fill_trie_with_ip(struct route_table_entry* rt_entry, int rtable_len) {
    //first we create our root node
    struct TrieNode* root = create_node();
    int cont = 0;
    
    for (int i = 0; i < rtable_len; ++i) {
        insert_ip(root, &rt_entry[i]);
        cont++;
    }

    return root;
}
// in trie fill we should have a dummy root node 

struct route_table_entry* get_best_route_trie(uint32_t ip_dest1, struct TrieNode* root) {

    int i = 31;
    uint32_t ip_dest = ntohl(ip_dest1);
    struct route_table_entry* best_route = NULL;
    
    while(root != NULL && i >= 0) {
        if (root->rt_entry != NULL) {
            best_route = root->rt_entry;
        }
        if ((ip_dest & (1 << i)) == 0) {
            //bit is 0 
            root = root->left;
        } else {
            //bit is 1
            root = root->right;
        }
        i--;
    }
    return best_route;
}