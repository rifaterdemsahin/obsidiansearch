#!/usr/bin/env python3
"""
Obsidian Keyword Search Tool
Search for keywords across your Git-hosted Obsidian vault with advanced filtering and export options.
"""

import os
import re
import json
import argparse
import subprocess
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Set
import tempfile
import shutil

@dataclass
class SearchResult:
    file_path: str
    line_number: int
    line_content: str
    context_before: List[str]
    context_after: List[str]
    match_type: str  # 'exact', 'case_insensitive', 'regex'
    timestamp: str

@dataclass
class FileResult:
    file_path: str
    total_matches: int
    matches: List[SearchResult]
    file_size: int
    last_modified: str
    tags: List[str]
    links: List[str]

class ObsidianSearcher:
    def __init__(self, vault_path: str = None, git_repo_url: str = None):
        self.vault_path = vault_path
        self.git_repo_url = git_repo_url
        self.temp_dir = None
        
    def clone_or_update_repo(self) -> str:
        """Clone the Git repository or update if it exists locally."""
        if not self.git_repo_url:
            raise ValueError("Git repository URL is required")
            
        # Create temp directory for cloning
        self.temp_dir = tempfile.mkdtemp(prefix="obsidian_search_")
        repo_name = self.git_repo_url.split('/')[-1].replace('.git', '')
        local_repo_path = os.path.join(self.temp_dir, repo_name)
        
        try:
            print(f"Cloning repository to {local_repo_path}...")
            subprocess.run([
                'git', 'clone', self.git_repo_url, local_repo_path
            ], check=True, capture_output=True, text=True)
            
            self.vault_path = local_repo_path
            return local_repo_path
            
        except subprocess.CalledProcessError as e:
            raise Exception(f"Failed to clone repository: {e.stderr}")
    
    def cleanup(self):
        """Clean up temporary directory."""
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def get_markdown_files(self) -> List[Path]:
        """Get all markdown files in the vault."""
        if not self.vault_path or not os.path.exists(self.vault_path):
            raise ValueError("Vault path does not exist")
            
        vault_path = Path(self.vault_path)
        markdown_files = []
        
        for file_path in vault_path.rglob("*.md"):
            # Skip hidden files and directories
            if not any(part.startswith('.') for part in file_path.parts):
                markdown_files.append(file_path)
                
        return markdown_files
    
    def extract_obsidian_metadata(self, content: str) -> Dict:
        """Extract Obsidian-specific metadata like tags and links."""
        # Extract tags (#tag or #nested/tag)
        tags = re.findall(r'#([a-zA-Z0-9_/-]+)', content)
        
        # Extract wikilinks ([[link]] or [[link|alias]])
        wikilinks = re.findall(r'\[\[([^\]|]+)(?:\|[^\]]+)?\]\]', content)
        
        # Extract external links
        external_links = re.findall(r'\[([^\]]+)\]\(([^)]+)\)', content)
        
        return {
            'tags': list(set(tags)),
            'wikilinks': list(set(wikilinks)),
            'external_links': external_links
        }
    
    def search_in_file(self, file_path: Path, keyword: str, 
                      case_sensitive: bool = False, 
                      regex: bool = False,
                      context_lines: int = 2) -> Optional[FileResult]:
        """Search for keyword in a single file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                
            matches = []
            file_stats = file_path.stat()
            
            # Prepare search pattern
            if regex:
                pattern = re.compile(keyword if case_sensitive else keyword, 
                                   0 if case_sensitive else re.IGNORECASE)
                match_type = 'regex'
            else:
                search_text = keyword if case_sensitive else keyword.lower()
                match_type = 'exact' if case_sensitive else 'case_insensitive'
            
            # Search through lines
            for i, line in enumerate(lines):
                line_to_search = line if case_sensitive else line.lower()
                found_match = False
                
                if regex:
                    if pattern.search(line):
                        found_match = True
                else:
                    if search_text in line_to_search:
                        found_match = True
                
                if found_match:
                    # Get context lines
                    context_before = []
                    context_after = []
                    
                    for j in range(max(0, i - context_lines), i):
                        context_before.append(lines[j].rstrip())
                    
                    for j in range(i + 1, min(len(lines), i + context_lines + 1)):
                        context_after.append(lines[j].rstrip())
                    
                    match = SearchResult(
                        file_path=str(file_path.relative_to(self.vault_path)),
                        line_number=i + 1,
                        line_content=line.rstrip(),
                        context_before=context_before,
                        context_after=context_after,
                        match_type=match_type,
                        timestamp=datetime.now().isoformat()
                    )
                    matches.append(match)
            
            if matches:
                # Extract metadata
                content = ''.join(lines)
                metadata = self.extract_obsidian_metadata(content)
                
                return FileResult(
                    file_path=str(file_path.relative_to(self.vault_path)),
                    total_matches=len(matches),
                    matches=matches,
                    file_size=file_stats.st_size,
                    last_modified=datetime.fromtimestamp(file_stats.st_mtime).isoformat(),
                    tags=metadata['tags'],
                    links=metadata['wikilinks']
                )
                
        except Exception as e:
            print(f"Error searching in {file_path}: {e}")
            return None
    
    def search_vault(self, keyword: str, 
                    case_sensitive: bool = False,
                    regex: bool = False,
                    context_lines: int = 2,
                    file_filter: str = None) -> List[FileResult]:
        """Search for keyword across the entire vault."""
        if not self.vault_path:
            if self.git_repo_url:
                self.clone_or_update_repo()
            else:
                raise ValueError("Either vault_path or git_repo_url must be provided")
        
        markdown_files = self.get_markdown_files()
        results = []
        
        # Apply file filter if provided
        if file_filter:
            filter_pattern = re.compile(file_filter, re.IGNORECASE)
            markdown_files = [f for f in markdown_files if filter_pattern.search(str(f))]
        
        print(f"Searching {len(markdown_files)} files for '{keyword}'...")
        
        for file_path in markdown_files:
            file_result = self.search_in_file(
                file_path, keyword, case_sensitive, regex, context_lines
            )
            if file_result:
                results.append(file_result)
        
        return results
    
    def export_results(self, results: List[FileResult], output_format: str = 'json') -> str:
        """Export search results in various formats."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if output_format.lower() == 'json':
            filename = f"obsidian_search_results_{timestamp}.json"
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump([asdict(result) for result in results], f, indent=2, ensure_ascii=False)
        
        elif output_format.lower() == 'markdown':
            filename = f"obsidian_search_results_{timestamp}.md"
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(f"# Obsidian Search Results\n\n")
                f.write(f"**Search completed:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                f.write(f"**Total files with matches:** {len(results)}\n\n")
                
                for file_result in results:
                    f.write(f"## {file_result.file_path}\n\n")
                    f.write(f"- **Matches:** {file_result.total_matches}\n")
                    f.write(f"- **File size:** {file_result.file_size} bytes\n")
                    f.write(f"- **Last modified:** {file_result.last_modified}\n")
                    
                    if file_result.tags:
                        f.write(f"- **Tags:** {', '.join(file_result.tags)}\n")
                    
                    if file_result.links:
                        f.write(f"- **Links:** {', '.join(file_result.links)}\n")
                    
                    f.write(f"\n### Matches\n\n")
                    
                    for match in file_result.matches:
                        f.write(f"**Line {match.line_number}:**\n")
                        f.write(f"```\n{match.line_content}\n```\n\n")
                        
                        if match.context_before or match.context_after:
                            f.write("**Context:**\n```\n")
                            for ctx_line in match.context_before:
                                f.write(f"  {ctx_line}\n")
                            f.write(f"> {match.line_content}\n")
                            for ctx_line in match.context_after:
                                f.write(f"  {ctx_line}\n")
                            f.write("```\n\n")
                    
                    f.write("---\n\n")
        
        elif output_format.lower() == 'csv':
            import csv
            filename = f"obsidian_search_results_{timestamp}.csv"
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'File Path', 'Line Number', 'Line Content', 'Match Type',
                    'File Size', 'Last Modified', 'Tags', 'Links'
                ])
                
                for file_result in results:
                    for match in file_result.matches:
                        writer.writerow([
                            file_result.file_path,
                            match.line_number,
                            match.line_content,
                            match.match_type,
                            file_result.file_size,
                            file_result.last_modified,
                            '; '.join(file_result.tags),
                            '; '.join(file_result.links)
                        ])
        
        return filename

def main():
    parser = argparse.ArgumentParser(description='Search for keywords in Git-hosted Obsidian vault')
    parser.add_argument('keyword', help='Keyword to search for')
    parser.add_argument('--vault-path', '-v', help='Local path to Obsidian vault')
    parser.add_argument('--git-url', '-g', help='Git repository URL for Obsidian vault')
    parser.add_argument('--case-sensitive', '-c', action='store_true', help='Case sensitive search')
    parser.add_argument('--regex', '-r', action='store_true', help='Use regex pattern matching')
    parser.add_argument('--context', '-ctx', type=int, default=2, help='Number of context lines (default: 2)')
    parser.add_argument('--file-filter', '-f', help='Regex filter for file names')
    parser.add_argument('--output-format', '-o', choices=['json', 'markdown', 'csv'], 
                       default='json', help='Output format (default: json)')
    parser.add_argument('--stats', '-s', action='store_true', help='Show search statistics')
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.vault_path and not args.git_url:
        parser.error("Either --vault-path or --git-url must be provided")
    
    searcher = ObsidianSearcher(args.vault_path, args.git_url)
    
    try:
        # Perform search
        results = searcher.search_vault(
            keyword=args.keyword,
            case_sensitive=args.case_sensitive,
            regex=args.regex,
            context_lines=args.context,
            file_filter=args.file_filter
        )
        
        # Display results summary
        total_matches = sum(r.total_matches for r in results)
        print(f"\nSearch Results:")
        print(f"- Keyword: '{args.keyword}'")
        print(f"- Files with matches: {len(results)}")
        print(f"- Total matches: {total_matches}")
        
        if args.stats:
            # Show detailed statistics
            print(f"\nDetailed Statistics:")
            file_types = {}
            tag_counts = {}
            
            for result in results:
                ext = Path(result.file_path).suffix
                file_types[ext] = file_types.get(ext, 0) + 1
                
                for tag in result.tags:
                    tag_counts[tag] = tag_counts.get(tag, 0) + 1
            
            print(f"File types: {dict(sorted(file_types.items()))}")
            if tag_counts:
                top_tags = sorted(tag_counts.items(), key=lambda x: x[1], reverse=True)[:10]
                print(f"Top tags: {dict(top_tags)}")
        
        # Export results
        if results:
            output_file = searcher.export_results(results, args.output_format)
            print(f"\nResults exported to: {output_file}")
        
        # Display first few matches for preview
        if results:
            print(f"\nPreview (first 3 matches):")
            count = 0
            for file_result in results:
                if count >= 3:
                    break
                for match in file_result.matches:
                    if count >= 3:
                        break
                    print(f"\n{file_result.file_path}:{match.line_number}")
                    print(f"  {match.line_content.strip()}")
                    count += 1
    
    except Exception as e:
        print(f"Error: {e}")
    finally:
        searcher.cleanup()

if __name__ == "__main__":
    main()
