import os
import google.generativeai as genai
from google.generativeai import types
from typing import List, Dict
import json

class GeminiChat:
    def __init__(self):
        genai.configure(api_key=os.environ.get("GEMINI_API_KEY"))
        self.model = genai.GenerativeModel('gemini-2.0-flash')
        self.chat_histories: Dict[str, List[types.Content]] = {}
        
    def _get_system_prompt(self) -> str:
        return """You are a legal contract generator. Generate a professional contract based on the user's requirements.
        Follow these guidelines:
        1. Create a clear, specific title
        2. Use formal legal language
        3. Include all necessary clauses and terms
        4. Add sections for dates and signatures
        5. Ensure the contract is legally sound and comprehensive
        
        Return the response in this JSON format:
        {
            "title": "Contract title here",
            "content": "Full contract content here"
        }
        """

    def start_new_chat(self, session_id: str) -> None:
        """Initialize a new chat session"""
        system_prompt = self._get_system_prompt()
        self.chat_histories[session_id] = [
            {
                "role": "user",
                "parts": [{"text": system_prompt}]
            },
            {
                "role": "model",
                "parts": [{"text": "I understand. I will generate professional contracts in JSON format with titles and content."}]
            }
        ]

    def generate_contract(self, prompt: str, session_id: str) -> dict:
        """Generate contract content while maintaining chat history"""
        if session_id not in self.chat_histories:
            self.start_new_chat(session_id)

        # Add user prompt to history
        self.chat_histories[session_id].append({
            "role": "user",
            "parts": [{"text": prompt}]
        })

        try:
            # Generate response using full chat history
            response = self.model.generate_content(
                contents=self.chat_histories[session_id],
                generation_config=genai.types.GenerationConfig(
                    temperature=0.7,
                    top_p=0.95,
                    top_k=40,
                    max_output_tokens=8192,
                )
            )

            # Get the response text
            full_response = response.text

            try:
                # Clean and parse the response
                clean_response = full_response.replace('```json', '').replace('```', '').strip()
                contract_data = json.loads(clean_response)

                # Add model response to history
                self.chat_histories[session_id].append({
                    "role": "model",
                    "parts": [{"text": full_response}]
                })

                return {
                    'success': True,
                    'title': contract_data['title'],
                    'content': contract_data['content']
                }

            except json.JSONDecodeError as e:
                return {
                    'success': False,
                    'message': f'Error parsing AI response: {str(e)}'
                }

        except Exception as e:
            return {
                'success': False,
                'message': f'Error generating contract: {str(e)}'
            }

    def clear_chat_history(self, session_id: str) -> None:
        """Clear chat history for a session"""
        if session_id in self.chat_histories:
            del self.chat_histories[session_id] 