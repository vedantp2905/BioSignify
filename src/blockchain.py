import hashlib
import json
import time
from typing import List, Dict, Any, Optional
import uuid
import os
from datetime import datetime
from src.database.supabase_adapter import SupabaseAdapter

class StorageType:
    FILE = "file"
    DATABASE = "database"

class Block:
    def __init__(self, index: int, timestamp: float, transactions: List[Dict], previous_hash: str):
        self.index = index
        self.timestamp = timestamp
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.nonce = 0
        self.hash = self.calculate_hash()
    
    def calculate_hash(self) -> str:
        # Sort transactions by ID to ensure consistent ordering
        sorted_transactions = sorted(self.transactions, key=lambda x: x.get('id', ''))
        
        # Create deterministic block string
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": sorted_transactions,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce
        }, sort_keys=True, separators=(',', ':'))  # Use compact separators
        
        # Hash using SHA-512
        return hashlib.sha512(block_string.encode('utf-8')).hexdigest()
    
    def mine_block(self, difficulty: int) -> None:
        """Mine a block by finding a hash with specified number of leading zeros"""
        target = "0" * difficulty
        
        while self.hash[:difficulty] != target:
            self.nonce += 1
            self.hash = self.calculate_hash()
    
    def to_dict(self) -> Dict:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": self.transactions,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
            "hash": self.hash
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'Block':
        """Create a Block instance from a dictionary"""
        block = cls(
            index=data['index'],
            timestamp=data['timestamp'],
            transactions=data['transactions'],
            previous_hash=data['previous_hash']
        )
        block.nonce = data['nonce']
        block.hash = data['hash']
        return block

class AgreementBlockchain:
    _instance = None
    
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self, storage_type: str = StorageType.FILE, 
                 storage_path: str = "data/blockchain.json"):
        if self._initialized:
            return
            
        self.storage_type = storage_type
        self.storage_path = storage_path
        self.chain = []
        self.pending_transactions = []
        self.difficulty = 4
        
        # Initialize storage
        if storage_type == StorageType.DATABASE:
            self.db = SupabaseAdapter()
            # Load chain from database
            self.chain = [Block.from_dict(b) for b in self.db.get_blocks()]
        else:
            self._load_chain()
            
        # Create genesis block if chain is empty
        if not self.chain:
            genesis_block = Block(
                index=0,
                timestamp=time.time(),
                transactions=[],
                previous_hash="0"
            )
            genesis_block.mine_block(self.difficulty)
            self.chain.append(genesis_block)
            if self.storage_type == StorageType.DATABASE:
                self.db.store_block(genesis_block.to_dict())
            
        self._initialized = True
    
    def _load_chain(self):
        """Load the blockchain from file storage"""
        # Create data directory if it doesn't exist
        os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)
        
        print(f"Initializing blockchain at: {self.storage_path}")
        
        # Load existing chain or create new one
        if os.path.exists(self.storage_path):
            try:
                with open(self.storage_path, 'r') as f:
                    chain_data = json.load(f)
                    self.chain = [Block.from_dict(b) for b in chain_data]
                print(f"Loaded {len(self.chain)} blocks from storage")
            except Exception as e:
                print(f"Error loading blockchain: {str(e)}")
                self.chain = [self.create_genesis_block()]
                self._save_chain()
        else:
            print("No existing blockchain found, creating new one")
            self.chain = [self.create_genesis_block()]
            self._save_chain()
            
        self.pending_transactions = []
    
    def _save_chain(self):
        """Save the blockchain to file"""
        try:
            chain_data = [block.to_dict() for block in self.chain]
            with open(self.storage_path, 'w') as f:
                json.dump(chain_data, f, indent=2)
            print(f"Saved {len(self.chain)} blocks to {self.storage_path}")
        except Exception as e:
            print(f"Error saving blockchain: {str(e)}")
    
    def create_genesis_block(self) -> Block:
        """Create the first block in the chain"""
        return Block(0, time.time(), [], "0")
    
    def get_latest_block(self) -> Block:
        return self.chain[-1]
    
    def add_agreement(self, agreement_id: str, recipient_email: str, embedding_reference: str, client_id: str, timestamp: float) -> str:
        """Add a new agreement to pending transactions"""
        transaction = {
            "id": str(uuid.uuid4()),
            "agreement_id": agreement_id,
            "recipient_email": recipient_email,
            "client_id": client_id,
            "embedding_reference": embedding_reference,
            "timestamp": timestamp  # Use provided timestamp
        }
        
        self.pending_transactions.append(transaction)
        return transaction["id"]
    
    def mine_pending_transactions(self) -> Block:
        """Create a new block with pending transactions and save to storage"""
        if not self.pending_transactions:
            return None
        
        latest_block = self.get_latest_block()
        
        # Use timestamp from first transaction for block consistency
        block_timestamp = self.pending_transactions[0]['timestamp']
        
        new_block = Block(
            index=latest_block.index + 1,
            timestamp=block_timestamp,  # Use transaction timestamp
            transactions=self.pending_transactions,
            previous_hash=latest_block.hash
        )
        
        # Mine the block
        new_block.mine_block(self.difficulty)
        
        # Add to chain and clear pending
        self.chain.append(new_block)
        
        if self.storage_type == StorageType.DATABASE:
            block_dict = new_block.to_dict()
            self.db.store_block(block_dict)
        else:
            self._save_chain()
        
        self.pending_transactions = []
        return new_block
    
    def is_chain_valid(self) -> bool:
        """Verify the integrity of the blockchain"""
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i-1]
            
            # Verify block hash
            if current_block.hash != current_block.calculate_hash():
                return False
                
            # Verify chain continuity
            if current_block.previous_hash != previous_block.hash:
                return False
                
        return True
    
    def get_transaction_by_id(self, transaction_id: str) -> Dict:
        """Retrieve a transaction by its ID"""
        for block in self.chain:
            for transaction in block.transactions:
                if transaction.get("id") == transaction_id:
                    return transaction
        return None
    
    def get_transactions_by_email(self, email: str) -> List[Dict]:
        """Retrieve all transactions associated with a specific email"""
        results = []
        for block in self.chain:
            for transaction in block.transactions:
                if transaction.get("recipient_email") == email:
                    results.append(transaction)
        return results
    
    def export_chain(self) -> str:
        """Export the entire blockchain as JSON"""
        serializable_chain = [block.to_dict() for block in self.chain]
        return json.dumps(serializable_chain, indent=2)
    
    def import_chain(self, chain_json: str) -> bool:
        """Import a blockchain from JSON"""
        try:
            chain_data = json.loads(chain_json)
            new_chain = []
            
            for block_data in chain_data:
                block = Block.from_dict(block_data)
                new_chain.append(block)
            
            # Validate the imported chain
            self.chain = new_chain
            if self.is_chain_valid():
                return True
            else:
                self.chain = [self.create_genesis_block()]
                return False
                
        except Exception as e:
            print(f"Error importing chain: {e}")
            return False
    
    def get_blocks(self) -> List[Dict]:
        """Get all blocks in the chain as dictionaries"""
        try:
            if self.storage_type == StorageType.DATABASE:
                # Get blocks from database
                db_blocks = self.db.get_blocks()
                # Convert database blocks to proper format
                parsed_blocks = []
                for b in db_blocks:
                    try:
                        transactions = b['transactions']
                        if isinstance(transactions, str):  # Fix database storage format issue
                            transactions = json.loads(transactions)
                        parsed_blocks.append({
                            'index': b['index'],
                            'timestamp': b['timestamp'],
                            'transactions': transactions,
                            'previous_hash': b['previous_hash'],
                            'nonce': b['nonce'],
                            'hash': b['hash']
                        })
                    except Exception as e:
                        print(f"Error parsing block {b.get('index')}: {str(e)}")
                return parsed_blocks
            else:
                # Get blocks from memory
                return [block.to_dict() for block in self.chain]
        except Exception as e:
            print(f"DEBUG - Error getting blocks: {str(e)}")
            import traceback
            print(f"DEBUG - Traceback: {traceback.format_exc()}")
            return []
    
    def get_agreement(self, agreement_id: str) -> Optional[Dict]:
        """Get agreement details from blockchain"""
        try:
            print(f"DEBUG - Getting agreement {agreement_id} from blockchain")
            # Get all blocks
            blocks = self.get_blocks()
            print(f"DEBUG - Found {len(blocks)} blocks")
            
            # Search through all transactions in all blocks
            for block in blocks:
                transactions = block.get('transactions', [])
                print(f"DEBUG - Checking block transactions: {transactions}")
                
                for transaction in transactions:
                    # Skip if transaction is not a dictionary
                    if not isinstance(transaction, dict):
                        print(f"DEBUG - Invalid transaction format: {transaction}")
                        continue
                        
                    if (transaction.get("agreement_id") == agreement_id and
                        not transaction.get("signature_timestamp")):  # Exclude signature transactions
                        print(f"DEBUG - Found agreement: {transaction}")
                        return transaction
                        
            print(f"DEBUG - No agreement found with ID: {agreement_id}")
            return None
            
        except Exception as e:
            print(f"DEBUG - Error in get_agreement: {str(e)}")
            import traceback
            print(f"DEBUG - Traceback: {traceback.format_exc()}")
            return None
    
    def add_signature(self, agreement_id: str, signature_timestamp: float, embedding_reference: str = None) -> str:
        """Add signature record to pending transactions"""
        transaction_id = str(uuid.uuid4())
        
        transaction = {
            "id": transaction_id,
            "type": "signature",
            "agreement_id": agreement_id,
            "signed_at": signature_timestamp,
            "embedding_reference": embedding_reference,
            "timestamp": signature_timestamp  # Use provided timestamp
        }
        
        self.pending_transactions.append(transaction)
        return transaction_id
    
    def add_cancellation(self, agreement_id: str, cancelled_by: str, timestamp: float) -> str:
        """Add cancellation record to pending transactions"""
        transaction = {
            "id": str(uuid.uuid4()),
            "type": "cancellation",
            "agreement_id": agreement_id,
            "cancelled_by": cancelled_by,
            "timestamp": timestamp
        }
        
        self.pending_transactions.append(transaction)
        return transaction["id"]

    def verify_agreement(self, agreement_id: str) -> dict:
        verification_result = {
            'is_valid': False,
            'block_number': None,
            'timestamp': None,
            'hash': None,
            'previous_hash': None,
            'details': [],
            'database_consistency': {
                'is_valid': True,
                'details': []
            }
        }
        
        # Get agreement details from database
        agreement_details = self.db.get_agreement(agreement_id)
        audit_trail = self.db.get_agreement_audit_trail(agreement_id)
        
        # Get all blocks and parse them
        blocks = self.db.get_blocks()
        parsed_blocks = []
        
        for block in blocks:
            if isinstance(block['transactions'], str):
                try:
                    block['transactions'] = json.loads(block['transactions'])
                except json.JSONDecodeError:
                    block['transactions'] = []
            parsed_blocks.append(block)
        
        # First verify blockchain integrity
        blockchain_verification = self._verify_blockchain_integrity(agreement_id, parsed_blocks)
        verification_result.update(blockchain_verification)
        
        # Then verify database consistency
        if agreement_details:
            # Verify creation transaction matches database
            creation_tx = next((tx for block in parsed_blocks 
                              for tx in block['transactions']
                              if tx.get('agreement_id') == agreement_id 
                              and not tx.get('type')), None)
            
            if creation_tx:
                # Check recipient email matches
                if creation_tx['recipient_email'] != agreement_details['recipient_email']:
                    verification_result['database_consistency']['is_valid'] = False
                    verification_result['database_consistency']['details'].append({
                        'type': 'data_mismatch',
                        'field': 'recipient_email',
                        'blockchain_value': creation_tx['recipient_email'],
                        'database_value': agreement_details['recipient_email']
                    })
                
                # Check status consistency
                signature_tx = next((tx for block in parsed_blocks 
                                   for tx in block['transactions']
                                   if tx.get('agreement_id') == agreement_id 
                                   and tx.get('type') == 'signature'), None)
                
                if signature_tx and agreement_details['status'] != 'signed':
                    verification_result['database_consistency']['is_valid'] = False
                    verification_result['database_consistency']['details'].append({
                        'type': 'status_mismatch',
                        'blockchain': 'signed',
                        'database': agreement_details['status']
                    })
                
                # Verify audit trail consistency
                for tx in (tx for block in parsed_blocks 
                          for tx in block['transactions']
                          if tx.get('agreement_id') == agreement_id):
                    
                    # Find matching audit log
                    matching_log = next((log for log in audit_trail 
                        if (tx.get('type') == 'signature' and log['action_type'] == 'signed') or
                           (tx.get('type') == 'cancellation' and log['action_type'] == 'cancelled') or
                           (not tx.get('type') and log['action_type'] == 'created')), None)
                    
                    if not matching_log:
                        verification_result['database_consistency']['is_valid'] = False
                        verification_result['database_consistency']['details'].append({
                            'type': 'missing_audit_log',
                            'transaction_type': tx.get('type', 'creation'),
                            'transaction_id': tx['id']
                        })
        
        # Update overall validity
        verification_result['is_valid'] = (
            verification_result['is_valid'] and 
            verification_result['database_consistency']['is_valid']
        )
        
        return verification_result

    def _verify_blockchain_integrity(self, agreement_id: str, parsed_blocks: List[Dict]) -> dict:
        verification_result = {
            'is_valid': False,
            'block_number': None,
            'timestamp': None,
            'hash': None,
            'previous_hash': None,
            'details': []
        }
        
        print("\n=== Starting Verification ===")
        print(f"Agreement ID: {agreement_id}")
        
        related_blocks = []
        creation_block = None
        
        for block in parsed_blocks:
            transactions = block['transactions']
            if isinstance(transactions, str):
                try:
                    transactions = json.loads(transactions)
                except json.JSONDecodeError:
                    transactions = []
            
            for tx in transactions:
                if tx.get('agreement_id') == agreement_id:
                    related_blocks.append(block)
                    if not creation_block and not tx.get('type'):
                        creation_block = block
                    break
        
        print(f"\nFound {len(related_blocks)} related blocks")
        
        if creation_block:
            verification_result.update({
                'block_number': creation_block['index'],
                'timestamp': creation_block['timestamp'],
                'hash': creation_block['hash'],
                'previous_hash': creation_block['previous_hash'],
                'is_valid': True  # Start as True, will be set to False if any verification fails
            })
            
            for block in related_blocks:
                print(f"\n=== Verifying Block #{block['index']} ===")
                print("Original Block Data:")
                print(json.dumps(block, indent=2))
                
                # Create Block instance with database values
                temp_block = Block(
                    index=block['index'],
                    timestamp=block['timestamp'],
                    transactions=block['transactions'],  # Now properly formatted
                    previous_hash=block['previous_hash']
                )
                
                # Use the stored nonce to verify hash
                temp_block.nonce = block['nonce']
                computed_hash = temp_block.calculate_hash()
                stored_hash = block['hash']
                
                print("\nVerification Results:")
                print(f"Block Index: {block['index']}")
                print(f"Nonce: {block['nonce']}")
                print(f"Computed Hash: {computed_hash}")
                print(f"Stored Hash:   {stored_hash}")
                
                # Verify:
                # 1. Hash matches when using stored nonce
                hash_valid = (computed_hash == stored_hash)
                # 2. Hash meets difficulty requirement
                mining_valid = stored_hash.startswith("0" * self.difficulty)
                
                # Check chain continuity using database blocks
                chain_valid = True
                if block['index'] > 0:
                    prev_block = next((b for b in parsed_blocks if b['index'] == block['index'] - 1), None)
                    if prev_block:
                        chain_valid = (block['previous_hash'] == prev_block['hash'])
                    else:
                        chain_valid = False
                
                # Update overall validity
                if not (hash_valid and mining_valid and chain_valid):
                    verification_result['is_valid'] = False
                
                verification_result['details'].append({
                    'type': 'block_verification',
                    'hash_valid': hash_valid and mining_valid,
                    'chain_valid': chain_valid,
                    'computed_hash': computed_hash,
                    'stored_hash': stored_hash,
                    'block_index': block['index'],
                    'original_nonce': block['nonce'],
                    'found_nonce': block['nonce'],
                    'message': (
                        f'Block #{block["index"]} integrity verified successfully' 
                        if hash_valid and mining_valid and chain_valid
                        else f'Block #{block["index"]} verification failed - ' + 
                             ('' if hash_valid else 'Hash mismatch. ') +
                             ('' if mining_valid else 'Invalid proof of work. ') +
                             ('' if chain_valid else 'Chain continuity broken.')
                    ).strip(),
                    'timestamp': block['timestamp']
                })
        
        return verification_result