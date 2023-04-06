#include "./include/queue.h"
#include "./include/lib.h"
#include "./include/protocols.h"
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
    uint32_t mask = htonl(rt_entry->mask);
    uint8_t i = 31, count = 0;

    while ((mask & (1 << i)) != 0 && count < 32) {
        count++;
        i--;
    }
    return count;
}

void insert_ip(struct TrieNode *root, struct route_table_entry* rt_entry) {

    uint8_t mask_length = get_mask_length(rt_entry);

	fprintf(stderr, "mask %u initial value %u\n", mask_length, htonl(rt_entry->mask));
    
    uint32_t prefix = htonl(rt_entry->prefix);
    struct TrieNode *root_copy = root;
    //computed the mask length 
    // now I have to go through every bit of the prefix and create whether 
    int i = 31;
    while (mask_length > 0) {
        //two cases I have bit 1 or 0
        if ((prefix & (1 << i)) == 0) {
            //bit is 0 
            //now we have another two cases whether there is a node already or not 
            if (root_copy->left == NULL) {
                // add new node 
                struct TrieNode* new_node = create_node();
                root_copy->left = new_node;
                root_copy = root_copy->left;
            }else {
                //just move to the next node 
                root_copy = root_copy->left;
            }
        } else {
            //bit is 1
            if (root_copy->right == NULL) {
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
    //theoretically we should add here the link to the entry
    root->rt_entry = rt_entry;

}

struct TrieNode* fill_trie_with_ip(struct route_table_entry* rt_entry, int rtable_len) {
    //first we create our root node
    struct TrieNode* root = create_node();
    int cont = 0;
    
	fprintf(stderr, "rtable_len %d \n", rtable_len);

    for (int i = 0; i < rtable_len; ++i) {
        insert_ip(root, &rt_entry[i]);
        cont++;
        
    }
	fprintf(stderr, "AAAAAAAcont %d \n", cont);


    return root;
}
// in trie fill we should have a dummy root node 

struct route_table_entry* get_best_route_trie(uint32_t ip_dest, struct TrieNode* root) {

    int i = 31;
    struct route_table_entry* best_route = NULL;
   // aici e problema merge pana la final afisez unde merge de fiecare data  
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
    if (best_route != NULL) {
    fprintf(stderr, "best route for ip: %u is interface %d and prefix %u\n", ip_dest, best_route->interface, best_route->prefix);
    } else {
        fprintf(stderr, "NULL ROUTE\n");
    }
    return best_route;
}

int main() {

    struct route_table_entry* entry = malloc(2 * sizeof(struct route_table_entry));
    
    entry[0].prefix = 13;
    entry[0].mask = 7;

    bin(entry[0].prefix);
    bin(entry[0].mask);

    struct TrieNode *root = fill_trie_with_ip(entry, 1);
    struct TrieNode *root_copy = root;

    //test
    if (root->left == NULL && root->right != NULL) {
        printf("prima linie is good\n");
    } else {
        printf("not good\n");
    }
    root = root->right;

    if (root->left != NULL && root->right == NULL) {
        printf("a doua linie is good\n");
    }
    root = root->left;

    if (root->left == NULL && root->right != NULL) {
        printf("a treia linie is good\n");
    }

    root = root->right;

    if (root->left == NULL && root->right == NULL) {
        printf("a patra linie is good\n");
    }
    if (root->rt_entry == &entry[0]) {
        printf("s-a salvat zaibisi adresa la entry\n");
    }

    struct route_table_entry* best_route= get_best_route_trie(61, root_copy);
    if (best_route == NULL) {
        printf("doesn't return pezdos\n");
    } else {
        printf("best route %d %d \n", best_route->mask, best_route->prefix);
    }
    return 0;
}