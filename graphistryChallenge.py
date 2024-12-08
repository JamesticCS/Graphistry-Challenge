import pandas as pd
from collections import deque, defaultdict
from datetime import datetime

class SecurityAnalyzer:
    def __init__(self, access_logs_df, activity_logs_df):
        self.access_logs = access_logs_df
        self.activity_logs = activity_logs_df
        self.visited_users = set()
        self.visited_computers = set()
        self.event_log = []
        self.affected_users = set()
        self.affected_computers = set()
        
        # Preprocessing: Build dictionaries for fast lookups
        self.user_to_computers = defaultdict(list)
        self.computer_activities = defaultdict(list)
        self.computer_to_users = defaultdict(list)
        
        for _, row in self.activity_logs.iterrows():
            self.user_to_computers[row['user_id']].append(row['computer_id'])
    
        for _, row in self.access_logs.iterrows():
            self.computer_activities[row['computer_id']].append((row['affected_user_id'], row['activity_type']))
            self.computer_to_users[row['computer_id']].append(row['affected_user_id'])
        
    def analyze_compromise(self, initial_user):
        """Perform breadth-first analysis of compromise spread"""
        queue = deque([initial_user])
        self.visited_users.add(initial_user)
        self.affected_users.add(initial_user)
        
        self.event_log.append(f"Analysis started with suspicious user {initial_user}")
        
        while queue:
            current_user = queue.popleft()
            self.event_log.append(f"Processing user: {current_user}")
            
            user_computers = self.user_to_computers.get(current_user, [])
            
            for computer in user_computers:
                if computer not in self.visited_computers:
                    self.visited_computers.add(computer)
                    self.affected_computers.add(computer)
                    self.event_log.append(f"User {current_user} accessed computer {computer}")
                    
                    self.event_log.append(f"Activities on computer {computer}:")
                    for (affected_user_id, activity_type) in self.computer_activities.get(computer, []):
                        self.event_log.append(f"  - {activity_type} by user {affected_user_id}")
                    
                    users_on_computer = self.computer_to_users.get(computer, [])
                    for user in users_on_computer:
                        if user not in self.visited_users:
                            self.affected_users.add(user)
                            self.visited_users.add(user)
                            queue.append(user)
                            self.event_log.append(f"Computer {computer} affected user {user}")
   
    def save_outputs(self):
        """Save analysis results to files"""
        # Save event log
        with open("investigation_log.txt", "w") as f:
            f.write("\n".join(self.event_log))
        
        # Save summary
        summary_data = {
            "Metric": [
                "Total Affected Users",
                "Total Affected Computers",
            ],
            "Value": [
                len(self.affected_users),
                len(self.affected_computers),
            ]
        }
        pd.DataFrame(summary_data).to_csv("analysis_summary.csv", index=False)

def main():
    # Load data
    access_logs = pd.read_csv("access_logs.csv")
    activity_logs = pd.read_csv("activity_logs.csv")

    # Initialize analyzer and run analysis starting from U1
    analyzer = SecurityAnalyzer(access_logs, activity_logs)
    analyzer.analyze_compromise("U1")

    # Save results
    analyzer.save_outputs()

    # Display summary
    print("\nFinal Summary:")
    print(f"Total Affected Users: {len(analyzer.affected_users)}")
    print(f"Total Affected Computers: {len(analyzer.affected_computers)}")
    print("\nResults have been saved to:")
    print("- investigation_log.txt (detailed event log)")
    print("- analysis_summary.csv (summary statistics)")

if __name__ == "__main__":
    main()

